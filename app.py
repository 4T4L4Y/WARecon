from flask import Flask, render_template, request, send_file, jsonify
import os,json,re

OUTPUTS_DIR = "outputs"
if not os.path.exists(OUTPUTS_DIR):
    os.makedirs(OUTPUTS_DIR)

app = Flask(__name__)

def run_naabu(domain, ports):
    if ports:
        command = f"naabu -host {domain} -p {ports} -o {OUTPUTS_DIR}/{domain}_naabu.txt"
    else:
        command = f"naabu -host {domain} -o {OUTPUTS_DIR}/{domain}_naabu.txt"
    print(command)
    os.system(command)
    print("[+] Naabu scan completed.")

def find_subdomains(domain, params):
    output_file = f"{OUTPUTS_DIR}/{domain}_subdomains.txt"
    if os.path.exists(output_file):
        os.remove(output_file)
    params_str = " ".join(params)
    command = f"subfinder -d {domain} {params_str} -o {output_file}"
    print(command)
    os.system(command)
    print("[+] Subdomain scan completed.")


def wayback_urls(domain, known_urls=False, include_subdomains=False):
    command_suffix = " "
    if known_urls:
        command_suffix += " --known_urls"
    if include_subdomains:
        command_suffix += " --subomains"
    with open(f"{OUTPUTS_DIR}/{domain}_subdomains.txt", 'r') as f:
        for subdomain in f.readlines():
            subdomain = subdomain.strip()
            output_file = f"{OUTPUTS_DIR}/{subdomain}_wayback.txt"
            if not os.path.exists(output_file):
                command = f"waybackpy -u {subdomain}{command_suffix} > {output_file}"
                print(command)
                os.system(command)



def run_httpx(domain, follow_redirects=False, show_status=False, match_codes=""):
    print("[+] Initiating URL scan with HTTPX...")
    wayback_files = [f for f in os.listdir(OUTPUTS_DIR) if f.endswith(f"{domain}_wayback.txt")]

    base_command = "httpx -nc"

    if follow_redirects:
        base_command += " -fr"

    if show_status:
        base_command += " -sc"

    if match_codes:
        base_command += f" -mc {match_codes}"

    if wayback_files:
        for wayback_file in wayback_files:
            output_file = f"{OUTPUTS_DIR}/{wayback_file.replace('_wayback.txt', '_httpx.txt')}"
            command = f"{base_command} -l {OUTPUTS_DIR}/{wayback_file} -o {output_file}"
            os.system(command)
    else:
        output_file = f"{OUTPUTS_DIR}/{domain}_httpx.txt"
        command = f"{base_command} -target {domain} -o {output_file}"
        print(command)
        os.system(command)

    print("[+] URL scan with HTTPX completed.")
def nuclei_scan(domain, raw_url, templates, severities):
    print("[+] Initiating Nuclei scan...")
    template_ids = templates.split(",")
    templates_str = " ".join(f"-id {template}" for template in template_ids) if templates else ""
    severity_str = "-severity " + ",".join(severities) if severities else ""
    output_txt = f"{OUTPUTS_DIR}/{domain}_nuclei.txt"
    output_json = f"{OUTPUTS_DIR}/{domain}_nuclei.json"
    command = f"nuclei -u {raw_url} {templates_str} {severity_str} -nh -nc -o {output_txt} -je {output_json}"
    print(command)
    os.system(command)
    print("[+] Nuclei scan completed.")
    return output_txt

def read_and_combine_results(directory, domain, file_suffix):
    combined_output = ""
    files = [f for f in os.listdir(directory) if f.endswith(file_suffix) and domain in f]
    for file in files:
        with open(os.path.join(directory, file), "r") as file_content:
            combined_output += file_content.read()
    return combined_output

def extract_domain(url):
    domain_regex = r"^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)"
    match = re.match(domain_regex, url)
    if match:
        return match.group(1)
    return url


@app.route("/", methods=["GET", "POST"])
def index():
    domain = ""
    naabu_output = ""
    subdomain_output = ""
    wayback_output = ""
    httpx_output = ""
    nuclei_output = ""


    if request.method == "POST":
        raw_url = request.form.get("domain")
        domain = extract_domain(raw_url)
        choices = request.form.getlist("choices")

        if '1' in choices:
            ports = request.form.get("naabuPorts", "")
            run_naabu(domain, ports)
            naabu_output = read_and_combine_results(OUTPUTS_DIR, domain, "_naabu.txt")

        if '2' in choices:
            subdomain_params = request.form.get("subdomainParams", "").split()  # Liste haline getir
            find_subdomains(domain, subdomain_params)
            subdomain_output = read_and_combine_results(OUTPUTS_DIR, domain, "_subdomains.txt")

        if '3' in choices:
            known_urls = request.form.get('waybackKnownUrls') == 'on'
            include_subdomains = request.form.get('includeSubdomains') == 'on'
            wayback_urls(domain, known_urls, include_subdomains)
            wayback_output = read_and_combine_results(OUTPUTS_DIR, domain, "_wayback.txt")

        if '4' in choices:
            follow_redirects = request.form.get('httpxFollowRedirects') == 'on'
            show_status = request.form.get('httpxStatusCode') == 'on'
            match_codes = request.form.get('httpxMatchCodes', '').replace(" ", "")
            run_httpx(domain, follow_redirects, show_status, match_codes)
            httpx_output = read_and_combine_results(OUTPUTS_DIR, domain, "_httpx.txt")

        if '5' in choices:
            nuclei_templates = request.form.get("nucleiTemplates", "")
            nuclei_severities = request.form.getlist("nucleiSeverity")
            nuclei_scan(domain, raw_url , nuclei_templates, nuclei_severities)
            nuclei_output = read_and_combine_results(OUTPUTS_DIR, domain, "_nuclei.txt")


    return render_template("index.html", domain=domain, naabu_output=naabu_output,
                           subdomain_output=subdomain_output, wayback_output=wayback_output,
                           httpx_output=httpx_output, nuclei_output=nuclei_output)

@app.route("/outputs/<path:filename>")
def download_file(filename):
    full_path = os.path.join(app.root_path,OUTPUTS_DIR,  filename)
    if os.path.exists(full_path):
        return send_file(full_path, as_attachment=True)
    else:
        return "Dosya Yok" , 404
if __name__ == "__main__":
    app.run(debug=False)

@app.route("/outputs/<domain>")
def nuclei_data(domain):
    path = os.path.join(app.root_path, OUTPUTS_DIR, f"{domain}_nuclei.json")
    try:
        with open(path, 'r') as file:
            data = json.load(file)
            return jsonify(data)
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404