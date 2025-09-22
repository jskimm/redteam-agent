#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Functions ---
log() {
  echo "[BUILD] $(date +'%Y-%m-%d %H:%M:%S') - $1"
}

# --- Main Execution ---
log "Starting dependency installation script..."

# --- 1. Install System Packages (nmap, go) ---
log "Checking operating system..."
if [[ "$(uname)" == "Darwin" ]]; then
  # macOS
  log "Detected macOS."
  if ! command -v brew &> /dev/null; then
    log "Homebrew not found. Please install it first by following the instructions at https://brew.sh/"
    exit 1
  fi
  log "Updating Homebrew and installing nmap and go..."
  brew install nmap go
elif [[ "$(uname)" == "Linux" ]]; then
  # Linux
  log "Detected Linux."
  if ! command -v apt-get &> /dev/null; then
    log "This script supports Debian/Ubuntu-based systems with apt-get. For other distributions, please install 'nmap' and 'golang-go' manually."
    exit 1
  fi
  log "Updating apt-get and installing nmap and golang-go..."
  sudo apt-get update
  sudo apt-get install -y nmap golang-go
else
  log "Unsupported operating system: $(uname). Please install 'nmap' and 'go' manually."
  exit 1
fi

# --- 2. Install Python Dependencies ---
log "Installing Python dependencies from requirements.txt..."
if ! command -v pip3 &> /dev/null; then
    log "pip3 not found. Please install Python 3 and pip."
    exit 1
fi
pip3 install -r requirements.txt --break-system-packages

# --- 3. Install Go-based Tools ---
log "Installing Go-based security tools..."
if ! command -v go &> /dev/null; then
    log "Go command not found. Please ensure Go is installed correctly."
    exit 1
fi

export GOBIN=$(go env GOPATH)/bin
export PATH=$PATH:$GOBIN

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

log "Installation Complete!"
log "--------------------------------------------------"
log "IMPORTANT: Please add the Go binary path to your shell configuration file."
log "Run the following command or add it to your ~/.zshrc, ~/.bashrc, or ~/.bash_profile:"

echo ""

echo "    export PATH=\$PATH:\$(go env GOPATH)/bin"

echo ""
log "After adding it, restart your terminal or run 'source ~/.zshrc' (or your respective config file) for the changes to take effect."
log "--------------------------------------------------"
