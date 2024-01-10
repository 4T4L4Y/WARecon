from flask import Flask, render_template, request
import os


subdomain_scan_done = False
app = Flask(__name__)

def run_naabu(domain):
    command = f"naabu -host {domain} -o {domain}_naabu.txt"
    os.system(command)
    print("[+] Naabu scan completed.")


def find_subdomains(domain):
    global subdomain_scan_done
    print("[+] Initiating subdomain scan...")
    output_file = f"{domain}_subdomains.txt"

    if os.path.exists(output_file):
        os.remove(output_file)

    command = f"subfinder -d {domain} -o {domain}_subdomains.txt"
    os.system(command)
    print("[+] Subdomain scan completed.")
    subdomain_scan_done = True


def wayback_urls(domain):
    if subdomain_scan_done:
        # If subdomain scan has been done
        with open(f"{domain}_subdomains.txt", 'r') as f:
            for subdomain in f.readlines():
                subdomain = subdomain.strip()
                if not os.path.exists(f"{subdomain}_wayback.txt"):
                    command = f"waybackpy -u {subdomain} --known_urls > {subdomain}_wayback.txt"
                    os.system(command)
    else:
        # If subdomain scan has not been done or if the wayback file doesn't exist
        if not os.path.exists(f"{domain}_subdomains.txt"):
            command = f"waybackpy -u {domain} --known_urls > {domain}_wayback.txt"
            os.system(command)
            print("[+] URL collection with Wayback Machine completed.")



def run_httpx(domain):
    print("[+] Initiating URL scan with HTTPX...")
    wayback_files = [f for f in os.listdir() if f.endswith(f"{domain}_wayback.txt")]

    if wayback_files:
        for wayback_file in wayback_files:
            command = f"httpx -l {wayback_file} -tech-detect  -fr -nc -sc -mc 200,302,400,401,403,404,500 -o {wayback_file.replace('_wayback.txt', '_httpx.txt')}"
            os.system(command)
    else:
        command = f"httpx -target {domain} -fr -nc -sc -mc 200,302,400,401,403,404,500 -o {domain}_httpx.txt"
        os.system(command)

    print("[+] URL scan with HTTPX completed.")

def nuclei_scan(domain):
    print("[+] Initiating Nuclei scan...")
    command = f"nuclei -u {domain} -nh -nc -o={domain}_nuclei.txt "
    os.system(command)
    print("[+] Nuclei scan completed.")


@app.route("/", methods=["GET", "POST"])
def index():
    subdomain_output = ""
    wayback_output = ""
    httpx_output = ""
    naabu_output = ""
    nuclei_output = ""

    if request.method == "POST":
        domain = request.form.get("domain")
        choices = request.form.getlist("choices")

        for choice in choices:
            choice = choice.strip()
            if choice == "1":
                run_naabu(domain)
                naabu_files = [f for f in os.listdir() if f.endswith("_naabu.txt") and domain in f]
                for naabu_file in naabu_files:
                    with open(naabu_file, "r") as naabu_file_content:
                        naabu_output += naabu_file_content.read()
            elif choice == "2":
                find_subdomains(domain)
                subdomain_files = [f for f in os.listdir() if f.endswith("_subdomains.txt") and domain in f]
                for subdomain_file in subdomain_files:
                    with open(subdomain_file, "r") as subdomain_file_content:
                        subdomain_output += subdomain_file_content.read()
            elif choice == "3":
                wayback_urls(domain)
                wayback_files = [f for f in os.listdir() if f.endswith("_wayback.txt") and domain in f]
                for wayback_file in wayback_files:
                    with open(wayback_file, "r") as wayback_file_content:
                        wayback_output += wayback_file_content.read()
            elif choice == "4":
                run_httpx(domain)
                httpx_files = [f for f in os.listdir() if f.endswith("_httpx.txt") and domain in f]
                for httpx_file in httpx_files:
                    with open(httpx_file, "r") as httpx_files_content:
                        httpx_output += httpx_files_content.read()
            elif choice == "5":
                nuclei_scan(domain)
                nuclei_files = [f for f in os.listdir() if f.endswith("_nuclei.txt") and domain in f]
                for nuclei_file in nuclei_files:
                    with open(nuclei_file,"r") as nuclei_files_content:
                        nuclei_output += nuclei_files_content.read()


    return render_template("index.html", naabu_output=naabu_output, subdomain_output=subdomain_output, wayback_output=wayback_output, httpx_output=httpx_output, nuclei_output=nuclei_output)

if __name__ == "__main__":
    app.run(debug=True)