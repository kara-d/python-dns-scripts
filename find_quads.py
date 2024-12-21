import subprocess
import csv

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

# Function to generate quad IPs and perform lookups
def find_quads_and_lookup():
    quads = []
    # Loop through all /8 blocks
    for i in range(1, 255):  # Range from 1 to 254
        quad_ip = f"{i}.{i}.{i}.{i}"
        print(f"Processing: {quad_ip}")  # Output progress to terminal
        dns_results = dig_lookup(quad_ip)
        whois_results = whois_lookup(quad_ip)
        host_status = ping_host(quad_ip)

        quad_data = {
            "IP": quad_ip,
            "A": dns_results["A"],
            "TXT": dns_results["TXT"],
            "DNSSEC": dns_results["DNSSEC"],
            "Owner": whois_results["Owner"],
            "Registrar": whois_results["Registrar"],
            "Registry": whois_results["Registry"],
            "Status": host_status,
        }
        quads.append(quad_data)

    return quads

# Write results to CSV
def write_to_csv(filename, data):
    with open(filename, "w", newline="") as csvfile:
        fieldnames = ["IP", "A", "TXT", "DNSSEC", "Owner", "Registrar", "Registry", "Status"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in data:
            writer.writerow(row)

# Write results to Markdown table
def write_to_markdown(filename, data):
    with open(filename, "w") as mdfile:
        # Write the table header
        mdfile.write("| IP Address | A Record | TXT Record | DNSSEC | Owner | Registrar | Registry | Status |\n")
        mdfile.write("|------------|----------|------------|--------|-------|-----------|----------|--------|\n")
        # Write each row
        for row in data:
            mdfile.write(f"| {row['IP']} | {row['A']} | {row['TXT']} | {row['DNSSEC']} | "
                         f"{row['Owner']} | {row['Registrar']} | {row['Registry']} | {row['Status']} |\n")

# Main function
def main():
    output_csv = "quads.csv"
    output_md = "quads.md"
    print("Finding quad IPs and performing DNS, WHOIS lookups, and ping tests...")
    quads = find_quads_and_lookup()
    
    # Output to terminal
    for quad in quads:
        print(
            f"IP: {quad['IP']}, A: {quad['A']}, TXT: {quad['TXT']}, DNSSEC: {quad['DNSSEC']}, "
            f"Owner: {quad['Owner']}, Registrar: {quad['Registrar']}, "
            f"Registry: {quad['Registry']}, Status: {quad['Status']}"
        )

    # Write results to files
    print(f"Writing results to {output_csv}...")
    write_to_csv(output_csv, quads)
    print(f"Writing results to {output_md}...")
    write_to_markdown(output_md, quads)
    print("Done!")

if __name__ == "__main__":
    main()

