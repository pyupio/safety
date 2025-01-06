test_json = {
  "meta": {
    "stage": "cicd",
    "scan_type": "scan",
    "telemetry": {
      "os_type": "Darwin",
      "os_release": "24.0.0",
      "safety_source": "cli",
      "os_description": "macOS-15.0.1-arm64-arm-64bit-Mach-O",
      "python_version": "3.13.1",
      "safety_command": "scan",
      "safety_options": {},
      "safety_version": "3.2.14"
    },
    "timestamp": "2025-01-06T16:48:13.830470Z",
    "authenticated": True,
    "scan_locations": ["."],
    "schema_version": "3.0",
    "authentication_method": "token"
  },
  "results": {},
  "scan_results": {
    "files": [],
    "projects": [
      {
        "id": "safety",
        "git": {
          "tag": "",
          "dirty": True,
          "branch": "test_repo",
          "commit": "9f9babca82839121ff7d2543af90181113c4c467",
          "origin": "https://github.com/pyupio/safety.git"
        },
        "files": [{
          "type": "requirements.txt",
          "location": "test_requirements.txt",
          "categories": ["python"],
          "results": {
            "dependencies": [
              {
                "name": "django",
                "specifications": [
                  {
                    "raw": "django==1.8.0",
                    "vulnerabilities": {
                      "remediation": {
                        "recommended": "4.2.17",
                        "other_recommended": ["5.1.4", "5.0.10"],
                        "vulnerabilities_found": 12
                      },
                      "known_vulnerabilities": [
                        {
                          "id": "59293",
                          "advisory": "Affected versions of Django are vulnerable to a potential ReDoS (regular expression denial of service) in EmailValidator and URLValidator via a very large number of domain name labels of emails and URLs.",
                          "cve": {
                            "name": "CVE-2023-36053",
                            "cvssv2": None,
                            "cvssv3": {
                              "base_score": 7.5,
                              "impact_score": 3.6,
                              "base_severity": "HIGH",
                              "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                            }
                          },
                          "ignored": {
                            "code": None,
                            "expires": None,
                            "reason": None
                          },
                          "vulnerable_spec": ">=4.0a1,<4.1.10"
                        },
                      ]
                    }
                  }
                ]
              },
            ]
          }
        }
        ]
      }
    ]
  }
}
