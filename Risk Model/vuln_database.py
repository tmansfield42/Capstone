VULN_DB = {
    "apache httpd": {
        "2.4.23": {
            "risk_score": 100,
            "cves": [
                {"cve": "CVE-2017-3167", "severity": "HIGH", "description": "Authentication bypass in mod_authnz_ldap"},
                {"cve": "CVE-2017-3169", "severity": "HIGH", "description": "mod_ssl input validation flaw"},
                {"cve": "CVE-2017-7668", "severity": "MEDIUM", "description": "Weak htpasswd parameter validation"},
                {"cve": "CVE-2017-7679", "severity": "HIGH", "description": "mod_mime buffer overflow (RCE)"},
                {"cve": "CVE-2017-9788", "severity": "HIGH", "description": "OptionsBleed memory disclosure"},
                {"cve": "CVE-2016-4979", "severity": "MEDIUM", "description": "mod_auth_digest insufficient randomness"}
            ]
        }
    }
}

