#!/bin/bash
set -e

echo "Naabu installing..."
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

echo "Subfinder installing..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "dnsx installing..."
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

echo "HTTPX installing..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo "Katana installing..."
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

echo "Nuclei installing..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo "Waybackpy installing..."
pip install waybackpy

echo "URO installing..."
pip install 'uro>=1.0.2,<2'

if command -v apt-get &>/dev/null; then
  echo "Nmap installing (system package)..."
  sudo apt-get install -y nmap 2>/dev/null || echo "Nmap: install manually with apt/brew"
fi

echo "Install completed."
