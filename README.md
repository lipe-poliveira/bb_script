# ProjectDiscovery
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest  
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest  | opcional (requer CHAOS_KEY)

# OWASP Amass
go install -v github.com/owasp-amass/amass/v4/...@latest

# tomnomnom
go install -v github.com/tomnomnom/assetfinder@latest

# findomain
macOS (brew):    brew install findomain
Linux (deb):     sudo apt-get install -y findomain   # (ou baixe do GitHub releases)


python3 recon.py -f wildcards.txt
# ou
python3 recon.py *.exemplo.com outra.com
