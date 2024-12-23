import subprocess
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_address

# Function to perform dig and extract DNS records and DNSSEC status
def dig_lookup(ip):
    results = {"IP": ip, "A": None, "TXT": None, "DNSSEC": None}
    try:
        # Perform A record lookup
        a_result = subprocess.run(
            ["dig", ip, "+short"],
            capture_output=True,
            text=True
        )
        results["A"] = a_result.stdout.strip() or "N/A"

        # Perform TXT record lookup
        txt_result = subprocess.run(
            ["dig", ip, "TXT", "+short"],
            capture_output=True,
            text=True
        )
        results["TXT"] = txt_result.stdout.strip() or "N/A"

        # Check DNSSEC
        dnssec_result = subprocess.run(
            ["dig", ip, "+dnssec", "+short"],
            capture_output=True,
            text=True
        )
        if "RRSIG" in dnssec_result.stdout:
            results["DNSSEC"] = "Enabled"
        else:
            results["DNSSEC"] = "Disabled"

    except Exception as e:
        error_message = f"Error: {e}"
        results["A"] = error_message
        results["TXT"] = error_message
        results["DNSSEC"] = error_message

    return results

# Function to perform WHOIS lookup
def whois_lookup(ip):
    results = {"Owner": None, "Registrar": None, "Registry": None}
    try:
        whois_result = subprocess.run(
            ["whois", ip],
            capture_output=True,
            text=True
        )
        output = whois_result.stdout
        # Parse owner, registrar, and registry from WHOIS output
        for line in output.splitlines():
            if "OrgName" in line or "Organization" in line:
                results["Owner"] = line.split(":", 1)[1].strip()
            if "Registrar" in line or "Registrar Name" in line:
                results["Registrar"] = line.split(":", 1)[1].strip()
            if "source" in line.lower() or "Registry" in line:
                results["Registry"] = line.split(":", 1)[1].strip()

        results["Owner"] = results["Owner"] or "N/A"
        results["Registrar"] = results["Registrar"] or "N/A"
        results["Registry"] = results["Registry"] or "N/A"
    except Exception as e:
        error_message = f"Error: {e}"
        results["Owner"] = error_message
        results["Registrar"] = error_message
        results["Registry"] = error_message

    return results

# Function to find ASN using whois
def find_asn(ip):
    try:
        asn_result = subprocess.run(
            ["whois", "-h", "whois.cymru.com", f" -v {ip}"],
            capture_output=True,
            text=True
        )
        # Parse ASN from the output
        lines = asn_result.stdout.splitlines()
        if len(lines) > 1:
            return lines[1].split('|')[0].strip()
        else:
            return "N/A"
    except Exception as e:
        return f"Error: {e}"

# Function to ping the IP address
def ping_host(ip):
    try:
        ping_result = subprocess.run(
            ["ping", "-c", "1", ip],
            capture_output=True,
            text=True
        )
        if ping_result.returncode == 0:
            return "Up"
        else:
            return "Down"
    except Exception as e:
        return f"Error: {e}"

# Function to process a single IP address
def process_ip(ip):
    print(f"Processing: {ip}")  # Output progress to terminal
    dns_results = dig_lookup(ip)
    whois_results = whois_lookup(ip)
    asn = find_asn(ip)
    host_status = ping_host(ip)

    return {
        "IP": ip,
        "A": dns_results["A"],
        "TXT": dns_results["TXT"],
        "DNSSEC": dns_results["DNSSEC"],
        "Owner": whois_results["Owner"],
        "Registrar": whois_results["Registrar"],
        "Registry": whois_results["Registry"],
        "ASN": asn,
        "Status": host_status,
    }

# Function to write results to CSV
def write_to_csv(filename, data):
    with open(filename, "w", newline="") as csvfile:
        fieldnames = ["IP", "A", "TXT", "DNSSEC", "Owner", "Registrar", "Registry", "ASN", "Status"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in data:
            writer.writerow(row)

# Function to write results to Markdown
def write_to_markdown(filename, data):
    with open(filename, "w") as mdfile:
        # Write the table header
        mdfile.write("| IP Address | A Record | TXT Record | DNSSEC | Owner | Registrar | Registry | ASN | Status |\n")
        mdfile.write("|------------|----------|------------|--------|-------|-----------|----------|-----|--------|\n")
        # Write each row
        for row in data:
            mdfile.write(f"| {row['IP']} | {row['A']} | {row['TXT']} | {row['DNSSEC']} | "
                         f"{row['Owner']} | {row['Registrar']} | {row['Registry']} | {row['ASN']} | {row['Status']} |\n")

# Main function with parallel processing
def main():
    output_csv = "quads.csv"
    output_md = "quads.md"
    ips = [f"{i}.{i}.{i}.{i}" for i in range(1, 255)]  # Generate quad IPs
    results = []

    print("Finding quad IPs and performing DNS, WHOIS lookups, ASN lookups, and ping tests in parallel...")

    # Process IPs in parallel with a limit of 10 threads
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {executor.submit(process_ip, ip): ip for ip in ips}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                print(f"Error processing {ip}: {e}")

    # Sort results by numerical IP order
    results.sort(key=lambda x: ip_address(x["IP"]))

    # Write results to files
    print(f"Writing results to {output_csv}...")
    write_to_csv(output_csv, results)
    print(f"Writing results to {output_md}...")
    write_to_markdown(output_md, results)
    print("Done!")

if __name__ == "__main__":
    main()

