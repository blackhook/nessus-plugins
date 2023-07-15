#%NASL_MIN_LEVEL 70300
#
# (c) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124766);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2018-15909",
    "CVE-2018-15910",
    "CVE-2018-15911",
    "CVE-2018-16513",
    "CVE-2018-18284",
    "CVE-2019-11507",
    "CVE-2019-11508",
    "CVE-2019-11509",
    "CVE-2019-11510",
    "CVE-2019-11538",
    "CVE-2019-11539",
    "CVE-2019-11540",
    "CVE-2019-11541",
    "CVE-2019-11542",
    "CVE-2019-11543"
  );
  script_bugtraq_id(105122, 107451, 108073);
  script_xref(name:"IAVA", value:"0001-A-0001-S");
  script_xref(name:"IAVA", value:"2019-A-0309-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/04/23");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CISA-NCAS", value:"AA22-011A");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");
  script_xref(name:"CEA-ID", value:"CEA-2020-0006");
  script_xref(name:"CEA-ID", value:"CEA-2020-0122");
  script_xref(name:"CEA-ID", value:"CEA-2019-0656");

  script_name(english:"Pulse Connect Secure Multiple Vulnerabilities (SA44101)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Pulse Connect
Secure running on the remote host is affected by multiple
vulnerabilities.

   - An arbitrary file read vulnerability exists in PCS. An
     unauthenticated, remote attacker can exploit this, via specially
     crafted URI, to read arbitrary files and disclose sensitive
     information. (CVE-2019-11510)

   - Multiple vulnerabilities are found in Ghostscript.(CVE-2018-16513
     , CVE-2018-18284, CVE-2018-15911, CVE-2018-15910, CVE-2018-15909)

   - A session hijacking vulnerability exists in PCS. An
     unauthenticated, remote attacker can exploit this, to perform
     actions in the user or administrator interface with the
     privileges of another user. (CVE-2019-11540)

   - An authentication leaks seen in users using SAML authentication
     with the reuse existing NC (Pulse) session option.
     (CVE-2019-11541)

   - Multiple vulnerabilities found in the admin web interface of PCS.
     (CVE-2019-11543, CVE-2019-11542, CVE-2019-11509, CVE-2019-11539)

   - Multiple vulnerabilities found in Network File Share (NFS) of PCS
     , allows the attacker to read/write arbitrary files on the
     affected device. (CVE-2019-11538, CVE-2019-11508)

   - A cross-site scripting (XSS) vulnerability exists in application
     launcher page due to improper validation of user-supplied input
     before returning it to users. An attacker can exploit this, by
     convincing a user to click a specially crafted URL, to execute
     arbitrary script code in a user's browser session.
     (CVE-2019-11507)

Refer to the vendor advisory for additional information.");
  # https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d23f9165");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the appropriate version referenced in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11540");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-11510");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Pulse Connect Secure File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Pulse Secure VPN Arbitrary Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulsesecure:pulse_connect_secure");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pulse_connect_secure_detect.nbin");
  script_require_keys("installed_sw/Pulse Connect Secure");

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('vcf_extras.inc');

port = get_http_port(default:443, embedded:TRUE);
app_info = vcf::pulse_connect_secure::get_app_info(app:'Pulse Connect Secure', port:port, full_version:TRUE, webapp:TRUE);

constraints = [
  {'min_version' : '8.3.1', 'fixed_version':'8.3.7.65025', 'fixed_display' : '8.3R7.1'},
  {'min_version' : '8.2.1', 'fixed_version':'8.2.12.64003', 'fixed_display' : '8.2R12.1'},
  {'min_version' : '8.1.1', 'fixed_version':'8.1.15.59747', 'fixed_display' : '8.1R15.1'},
  {'min_version' : '9.0.1', 'fixed_version':'9.0.3.64053', 'fixed_display' : '9.0R3.4 / 9.0R4'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
