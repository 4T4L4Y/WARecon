# WARecon

This web application serves as a comprehensive tool for domain analysis. It integrates various open-source tools to perform a range of functions including port scanning, subdomain discovery, historical URL retrieval from the Wayback Machine, live URL scanning, and vulnerability scanning. The application offers a user-friendly interface where users can input a domain and select the desired analysis tools. The backend processes include:

Naabu: Conducts a fast port scan to identify open ports.

Subfinder: Discovers subdomains associated with the main domain.

Waybackpy: Retrieves historical URLs from the Wayback Machine.

HTTPX: Scans for live URLs and their status codes.

Nuclei: Performs vulnerability scanning on the given domain.

The results of each tool are displayed on the web interface, providing a comprehensive view of the domain's security and infrastructure profile. Ideal for cybersecurity professionals and website administrators.

## Installing requirements

```bash
pip3 install -r requirements
```
## Installing tools

```bash
bash install_tools.sh
```

## Usage

Open terminal and run python3 app.py

Then the web interface will be ready at 127.0.0.1:5000


## Contact

[Musa ATALAY](https://tr.linkedin.com/in/musatalayy)

## Tools

[Naabu](https://github.com/projectdiscovery/naabu)
[Subfinder](https://github.com/projectdiscovery/subfinder)
[Waybackpy](https://pypi.org/project/waybackpy/)
[HTTPX](https://github.com/projectdiscovery/httpx)
[Nuclei](https://github.com/projectdiscovery/nuclei)

# Sorumluluk Reddi Beyanı

Bu web uygulaması, sadece eğitim ve bilgilendirme amaçlı olarak tasarlanmıştır. Uygulamanın kullanımı, kullanıcının sorumluluğundadır ve kullanıcılar, bu araçları kullanırken ilgili yasal düzenlemelere ve etik kurallara uymakla yükümlüdürler. Uygulama geliştiricisi, bu aracın kullanımından kaynaklanan herhangi bir zarar, veri kaybı veya başka herhangi bir doğrudan veya dolaylı zarar için hiçbir sorumluluk kabul etmez. Kullanıcılar, bu aracı kullanmadan önce hedeflenen sistem veya ağın yöneticilerinden izin almalıdır. Bu araç, izinsiz testler yapmak veya herhangi bir ağa, sisteme veya servise zarar vermek amacıyla kullanılamaz. Uygulamanın kullanımı, bu şartları kabul ettiğiniz anlamına gelir.
