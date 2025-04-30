from scanner.crawler import crawl_website

def scan_website(url, max_links=30):
    """
    Calls the crawler to scan the website, which already includes:
    - Crawling links & forms
    - Scanning for SQLi & XSS vulnerabilities
    - Performing port scanning
    - Logging & reporting results
    """
    return crawl_website(url, max_links)

# ✅ Example Usage
if __name__ == "__main__":
    max_links = int(input("Enter max links to crawl: "))
    target_url = input("Enter target URL: ")

    results = scan_website(target_url, max_links)

    print("\n🔍 Scan Report for:", results["status"])
    
    if results["status"] == "error":
        print(f"❌ Error: {results['message']}")
    else:
        print(f"🔗 Links Found: {len(results['links'])}")
        print(f"📝 Forms Found: {len(results['forms'])}")
        print(f"🔌 Open Ports: {', '.join(map(str, results['open_ports'])) if results['open_ports'] else 'None'}\n")

        print("🛡️ Detected Vulnerabilities:")
        if results["vulnerabilities"]:
            for vuln in results["vulnerabilities"]:
                print(f"\n⚠️ Type: {vuln['type']}")
                print(f"   🔎 URL: {vuln['url']}")
                print(f"   📜 Details: {vuln['details']}")
                if "form_inputs" in vuln:
                    print(f"   📝 Form Inputs: {', '.join(vuln['form_inputs'])}")
        else:
            print("✅ No vulnerabilities detected!")

        print(f"\n📄 Report saved at: {results['report']}")
