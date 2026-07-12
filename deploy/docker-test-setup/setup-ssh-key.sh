#!/bin/bash
# SSH Key Setup Script for Automated VPS Access
# Run this ONCE from your local machine to enable passwordless SSH access

set -e

VPS_IP="${VPS_IP:?Set VPS_IP environment variable to your test VPS address}"
VPS_USER="${VPS_USER:-root}"
VPS_PASSWORD="${VPS_PASSWORD:?Set VPS_PASSWORD environment variable (never hardcode credentials)}"

echo "=== SSH Key Setup for $VPS_USER@$VPS_IP ==="
echo ""

# Check if SSH key already exists
if [ -f "$HOME/.ssh/id_rsa" ]; then
    echo "✓ SSH key already exists at ~/.ssh/id_rsa"
else
    echo "Creating new SSH key..."
    ssh-keygen -t rsa -b 4096 -f "$HOME/.ssh/id_rsa" -N ""
    echo "✓ SSH key created"
fi

echo ""
echo "Installing key on remote server..."

# Use sshpass if available, or provide manual instructions
if command -v sshpass &> /dev/null; then
    sshpass -p "$VPS_PASSWORD" ssh-copy-id -o StrictHostKeyChecking=no "$VPS_USER@$VPS_IP"
    echo "✓ SSH key installed using sshpass"
else
    echo ""
    echo "sshpass not found. Please run manually:"
    echo "  ssh-copy-id $VPS_USER@$VPS_IP"
    echo ""
    echo "Or install sshpass:"
    case "$(uname -s)" in
        Linux*)
            if command -v apt-get &> /dev/null; then
                echo "  sudo apt-get install sshpass"
            elif command -v yum &> /dev/null; then
                echo "  sudo yum install sshpass"
            fi
            ;;
        Darwin*)
            echo "  brew install hudochenkov/sshpass/sshpass"
            ;;
        MINGW*|CYGWIN*|MSYS*)
            echo "  # Download from: https://github.com/kevinburke/sshpass/releases"
            echo "  # Or use Git Bash with: curl -L https://raw.githubusercontent.com/kevinburke/sshpass/master/sshpass > /usr/bin/sshpass"
            ;;
    esac
    echo ""
    exit 1
fi

echo ""
echo "Testing SSH connection..."
if ssh -o StrictHostKeyChecking=no "$VPS_USER@$VPS_IP" "echo '✓ SSH access successful'"; then
    echo ""
    echo "✓ SSH key setup complete!"
    echo ""
    echo "You can now SSH without password:"
    echo "  ssh $VPS_USER@$VPS_IP"
else
    echo "✗ SSH connection failed"
    exit 1
fi
