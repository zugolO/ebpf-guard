# SSH Key Setup Script for Windows PowerShell
# Run this ONCE to enable passwordless SSH access to VPS

$VPS_IP = $env:VPS_IP
$VPS_USER = if ($env:VPS_USER) { $env:VPS_USER } else { "root" }
$VPS_PASSWORD = $env:VPS_PASSWORD
if (-not $VPS_IP -or -not $VPS_PASSWORD) {
    Write-Error "Set VPS_IP and VPS_PASSWORD environment variables before running this script (never hardcode credentials)."
    exit 1
}

Write-Host "=== SSH Key Setup for $VPS_USER@$VPS_IP ===" -ForegroundColor Green
Write-Host ""

# Check if OpenSSH is available
$sshAvailable = Get-Command ssh -ErrorAction SilentlyContinue
if (-not $sshAvailable) {
    Write-Host "OpenSSH not found. Installing..." -ForegroundColor Yellow

    # For Windows 10/11, OpenSSH is available as optional feature
    try {
        Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 -ErrorAction Stop
        Write-Host "✓ OpenSSH installed" -ForegroundColor Green
    } catch {
        Write-Host "✗ Failed to install OpenSSH" -ForegroundColor Red
        Write-Host "Please install it manually via Windows Settings > Apps > Optional Features" -ForegroundColor Yellow
        exit 1
    }
}

# Check if SSH key exists
$sshDir = Join-Path $env:USERPROFILE ".ssh"
$keyPath = Join-Path $sshDir "id_rsa"

if (-not (Test-Path $sshDir)) {
    New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
    Write-Host "✓ Created .ssh directory" -ForegroundColor Green
}

if (Test-Path $keyPath) {
    Write-Host "✓ SSH key already exists at $keyPath" -ForegroundColor Green
} else {
    Write-Host "Creating new SSH key..." -ForegroundColor Yellow
    ssh-keygen -t rsa -b 4096 -f $keyPath -N ""
    Write-Host "✓ SSH key created" -ForegroundColor Green
}

# Generate public key if missing
$pubKeyPath = "$keyPath.pub"
if (-not (Test-Path $pubKeyPath)) {
    Write-Host "Generating public key..." -ForegroundColor Yellow
    ssh-keygen -y -f $keyPath > $pubKeyPath
}

Write-Host ""
Write-Host "Installing key on remote server..." -ForegroundColor Yellow

# Read public key
$publicKey = Get-Content $pubKeyPath -Raw

# Create SSH command to install the key
$sshCommand = @"
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo '$publicKey' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
echo '✓ Key installed on server'
"@

# Try using plink (PuTTY) if available, otherwise use ssh
$plinkPath = Get-Command plink -ErrorAction SilentlyContinue

if ($plinkPath) {
    Write-Host "Using plink for SSH connection..." -ForegroundColor Cyan
    $echo = echo y | plink -ssh -l $VPS_USER -pw $VPS_PASSWORD $VPS_IP $sshCommand
} else {
    Write-Host "Using OpenSSH for connection..." -ForegroundColor Cyan
    Write-Host "When prompted, enter password: $VPS_PASSWORD" -ForegroundColor Yellow

    # Use ssh with expect-like behavior
    $sshCommandEscaped = $sshCommand -replace '`', '``' -replace '"', '`"'

    # Create temporary batch file for the command
    $tempFile = [System.IO.Path]::GetTempFileName()
    Set-Content -Path $tempFile -Value $sshCommandEscaped

    try {
        $result = ssh -o StrictHostKeyChecking=no "$VPS_USER@$VPS_IP" "bash -s" < $tempFile
        Write-Host $result
    } finally {
        Remove-Item $tempFile -Force
    }
}

Write-Host ""
Write-Host "Testing SSH connection..." -ForegroundColor Yellow

try {
    $testResult = ssh -o StrictHostKeyChecking=no "$VPS_USER@$VPS_IP" "echo '✓ SSH access successful'" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host $testResult -ForegroundColor Green
        Write-Host ""
        Write-Host "✓ SSH key setup complete!" -ForegroundColor Green
        Write-Host ""
        Write-Host "You can now SSH without password:" -ForegroundColor Cyan
        Write-Host "  ssh $VPS_USER@$VPS_IP" -ForegroundColor White
    } else {
        Write-Host "✗ SSH connection failed" -ForegroundColor Red
        Write-Host "You may need to manually copy the key:" -ForegroundColor Yellow
        Write-Host "  ssh-copy-id $VPS_USER@$VPS_IP" -ForegroundColor White
    }
} catch {
    Write-Host "✗ SSH connection failed: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "Manual setup:" -ForegroundColor Yellow
    Write-Host "1. Copy your public key:" -ForegroundColor White
    Write-Host "   type $pubKeyPath" -ForegroundColor Gray
    Write-Host "2. SSH to server: ssh $VPS_USER@$VPS_IP" -ForegroundColor White
    Write-Host "3. Add key to ~/.ssh/authorized_keys" -ForegroundColor White
}

Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
