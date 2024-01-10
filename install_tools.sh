#!/bin/bash

echo "Naabu yükleniyor..."
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

echo "Subfinder yükleniyor..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "Waybackpy yükleniyor..."
pip install waybackpy

echo "HTTPX yükleniyor..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo "Nuclei yükleniyor..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo "Yükleme işlemleri tamamlandı."
