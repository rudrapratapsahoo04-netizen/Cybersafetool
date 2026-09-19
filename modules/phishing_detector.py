from urllib.parse import urlparse
import re


# Suspicious words commonly found in phishing URLs
SUSPICIOUS_WORDS = {
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "password",
    "wallet",
    "banking",
    "signin",
    "confirm",
    "urgent",
    "free",
    "bonus"
}


# Common URL shortening services
SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "ow.ly"
}


def score_url(url):
    """
    Analyze a URL using simple heuristic rules.
    Returns a risk score, risk level and findings.
    """

    # Add HTTPS if protocol is missing
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url

    parsed = urlparse(url)

    host = (parsed.hostname or "").lower()

    score = 0
    findings = []


    # 1. HTTPS check
    if parsed.scheme != "https":
        score += 15
        findings.append("HTTPS is not used")


    # 2. URL length check
    if len(url) > 100:
        score += 15
        findings.append("Very long URL")


    # 3. @ symbol check
    if "@" in url:
        score += 20
        findings.append("@ symbol can obscure the destination")


    # 4. IP address instead of domain
    if host and re.fullmatch(
        r"\d{1,3}(?:\.\d{1,3}){3}",
        host
    ):
        score += 25
        findings.append("Hostname is an IP address")


    # 5. URL shortener check
    if host in SHORTENERS:
        score += 20
        findings.append("URL shortening service detected")


    # 6. Too many subdomains
    if host.count(".") >= 3:
        score += 10
        findings.append("Many hostname levels")


    # 7. Punycode check
    if host.startswith("xn--") or ".xn--" in host:
        score += 15
        findings.append("Punycode hostname detected")


    # 8. Too many hyphens
    if url.count("-") >= 3:
        score += 10
        findings.append("Many hyphens")


    # 9. Suspicious keywords
    words = set(
        re.findall(
            r"[a-zA-Z]{3,}",
            url.lower()
        )
    )

    hits = sorted(words & SUSPICIOUS_WORDS)

    if hits:
        score += min(20, 5 * len(hits))

        findings.append(
            "Suspicious keywords: " + ", ".join(hits)
        )


    # Maximum score = 100
    score = min(score, 100)


    # Risk level
    if score < 31:
        level = "LOW"
    elif score < 61:
        level = "MEDIUM"
    else:
        level = "HIGH"


    return {
        "url": url,
        "score": score,
        "level": level,
        "findings": findings
    }


def detect_phishing():

    print("\nPhishing URL Detector")
    print("-" * 40)

    url = input("URL to analyze: ").strip()


    # Empty URL check
    if not url:
        print("Error: Please enter a URL.")
        return


    try:
        result = score_url(url)

        print()
        print("Analyzed URL :", result["url"])
        print("Risk score   :", f"{result['score']}/100")
        print("Risk level   :", result["level"])


        # Display findings
        if result["findings"]:

            print("\nFindings:")

            for item in result["findings"]:
                print("[!] " + item)

        else:
            print("\n[+] No obvious heuristic indicators found.")


        print(
            "\nNote: heuristic detection is not proof "
            "that a URL is safe or malicious."
        )


    except Exception as error:

        print("Error:", error)