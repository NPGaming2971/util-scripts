function ConvertTo-QueryString {
    param($pairs)
    $pairs.GetEnumerator() |
    ForEach-Object { "{0}={1}" -f $_.Key, [uri]::EscapeDataString($_.Value) } |
    ForEach-Object -Begin { $s = "" } -Process { if ($s) { $s += "&" }; $s += $_ } -End { $s }
}

function Get-TokenCachePath {
    return Join-Path $env:TEMP 'gcs_oauth2_creds.json'
}

function Load-TokenCache {
    $path = Get-TokenCachePath
    if (Test-Path $path) {
        return Get-Content -Raw $path | ConvertFrom-Json
    }
    return $null
}

function Save-TokenCache {
    param($tokenObj)
    $path = Get-TokenCachePath
    $tokenObj | ConvertTo-Json -Depth 5 | Set-Content -Path $path -Encoding UTF8
}

function Ensure-PortFree {
    param([int]$port)
    try {
        $test = [System.Net.Sockets.TcpListener]::new([IPAddress]::Any, $port)
        $test.Start(); $test.Stop()
    }
    catch {
        throw "Port $port đang được sử dụng."
    }
}

function Start-LocalHttpListener {
    param([string]$prefix)
    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Clear()
    $listener.Prefixes.Add($prefix)
    try {
        $listener.Start()
        Write-Host "✅ Server đang nhận request ở $prefix"
        return $listener
    }
    catch {
        throw "Không thể khởi tạo server."
    }
}

function Wait-OAuthCallback {
    param([System.Net.HttpListener]$listener, [int]$timeoutSec = 300)
    Write-Host "Đang đợi tối đa ${timeoutSec}s cho OAuth callback..."
    $async = $listener.BeginGetContext($null, $null)
    if (-not $async.AsyncWaitHandle.WaitOne($timeoutSec * 1000)) {
        $listener.Stop(); $listener.Close()
        throw "Hết thời gian chờ đợi OAuth callback."
    }
    $context = $listener.EndGetContext($async)

    $response = $context.Response
    $html = '<html><body><h2>Authorization successful!</h2><p>You may return to the terminal.</p></body></html>'
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
    $response.ContentLength64 = $buffer.Length
    $response.ContentType = 'text/html'
    $response.OutputStream.Write($buffer, 0, $buffer.Length)
    $response.OutputStream.Close()

    $listener.Stop(); $listener.Close()
    return $context.Request.Url.Query
}

function Get-OAuthToken {
    param($clientId, $clientSecret, $redirectUri)

    $cached = Load-TokenCache
    if ($cached -and $cached.access_token -and $cached.refresh_token) {
        try {
            Write-Host "🔄 Đang thử refresh access token..."
            $params = @{
                client_id     = $clientId
                client_secret = $clientSecret
                refresh_token = $cached.refresh_token
                grant_type    = 'refresh_token'
            }
            $resp = Invoke-RestMethod -Method Post -Uri 'https://oauth2.googleapis.com/token' `
                -ContentType 'application/x-www-form-urlencoded' -Body (ConvertTo-QueryString $params)

            $resp | Add-Member NoteProperty refresh_token $cached.refresh_token -Force
            Save-TokenCache $resp
            return $resp
        }
        catch {
            Write-Warning "⚠️ Refresh token không còn hợp lệ, cần xác thực lại."
        }
    }

    # Do full auth code flow
    $port = ([uri]$redirectUri).Port
    Ensure-PortFree -port $port
    $listener = Start-LocalHttpListener -prefix $redirectUri

    $scope = 'https://www.googleapis.com/auth/cloud-platform'
    $authUrl = "https://accounts.google.com/o/oauth2/v2/auth?redirect_uri=$([uri]::EscapeDataString($redirectUri))&prompt=consent&response_type=code&client_id=$clientId&scope=$([uri]::EscapeDataString($scope))&access_type=offline"
    Start-Process $authUrl
    Write-Host "📤 Đang mở trình duyệt xác thực người dùng..."

    $query = Wait-OAuthCallback -listener $listener
    if ($query -notmatch 'code=([^&]+)') {
        throw "Không tìm thấy code auth trong URL callback."
    }
    $authCode = $matches[1]
    Write-Host "✅ Nhận được mã xác thực."

    $params = @{
        code          = $authCode
        client_id     = $clientId
        client_secret = $clientSecret
        redirect_uri  = $redirectUri
        grant_type    = 'authorization_code'
    }

    $resp = Invoke-RestMethod -Method Post -Uri 'https://oauth2.googleapis.com/token' `
        -ContentType 'application/x-www-form-urlencoded' -Body (ConvertTo-QueryString $params)

    Save-TokenCache $resp
    return $resp
}

function Ensure-SshKey {
    param($PublicKeyPath, $PrivateKeyPath)
    $sshDir = Split-Path -Parent $PublicKeyPath
    if (-not(Test-Path $sshDir)) { New-Item -ItemType Directory -Path $sshDir | Out-Null }
    if (-not(Test-Path $PrivateKeyPath) -or -not(Test-Path $PublicKeyPath)) {
        Write-Host "🔐 Đang tạo SSH key ở $PrivateKeyPath..."
        ssh-keygen -t rsa -b 2048 -f $PrivateKeyPath -N ''
    }
    $raw = (Get-Content -Raw $PublicKeyPath).Trim()
    $kp = $raw -split ' '
    return "$($kp[0]) $($kp[1])"
}

function Invoke-CloudShellApi {
    param($accessToken, $Method, $Uri, $Body = $null)
    $headers = @{ Authorization = "Bearer $accessToken" }
    if ($Body) { $Body = $Body | ConvertTo-Json -Depth 5 }
    Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $Body -ContentType 'application/json'
}

function Start-GCloudShellWithOAuth {
    [CmdletBinding()]
    param(
        [string]$PublicKeyPath = "$HOME/.ssh/id_rsa.pub",
        [string]$PrivateKeyPath = "$HOME/.ssh/id_rsa",
        [string]$Environment = 'default',
        [string]$Command = ''
    )

    $clientId     = '-'
    $clientSecret = '-'
    $redirectUri  = "http://localhost:5931/"

    $token = Get-OAuthToken -clientId $clientId -clientSecret $clientSecret -redirectUri $redirectUri
    $accessToken = $token.access_token
    if (-not $accessToken) { throw 'Không lấy được access token.' }

    $pubKey = Ensure-SshKey -PublicKeyPath $PublicKeyPath -PrivateKeyPath $PrivateKeyPath
    $base = "https://content-cloudshell.googleapis.com/v1/users/me/environments/$Environment"

    Invoke-CloudShellApi -accessToken $accessToken -Method Post -Uri "${base}:addPublicKey" -Body @{ key = $pubKey }
    Invoke-CloudShellApi -accessToken $accessToken -Method Post -Uri "${base}:start" -Body @{ accessToken = $accessToken; publicKeys = @($pubKey) }

    Write-Host "⏳ Đang đợi Cloud Shell khởi động..."
    do {
        Start-Sleep 2
        $env = Invoke-CloudShellApi -accessToken $accessToken -Method Get -Uri $base
        Write-Host -NoNewline '.'
    } until ($env.state -eq 'RUNNING')
    Write-Host "`n✅ Shell RUNNING"

    $sshHost     = $env.sshHost
    $sshPort     = $env.sshPort
    $sshUsername = $env.sshUsername

    $sshCmd = if ($Command) {
        "`"$Command`""
    } else {
        ''
    }

    try {
        Write-Host "🔗 Đang SSH tới ${sshUsername}@${sshHost}:${sshPort}..."
        & ssh -t -o ServerAliveInterval=60 -o ServerAliveCountMax=5 -i $PrivateKeyPath -p $sshPort "${sshUsername}@${sshHost}" $sshCmd
    }
    catch {
        throw "SSH session thất bại."
    }
}

Start-GCloudShellWithOAuth