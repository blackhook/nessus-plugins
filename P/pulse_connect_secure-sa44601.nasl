#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(142058);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2015-9251",
    "CVE-2019-11358",
    "CVE-2020-8255",
    "CVE-2020-8260",
    "CVE-2020-8261",
    "CVE-2020-8262",
    "CVE-2020-8263",
    "CVE-2020-15352"
  );
  script_xref(name:"IAVA", value:"2020-A-0495");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/04/23");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Pulse Connect Secure < 9.1R9 (SA44601)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Pulse Connect Secure running on the remote host is prior 
to 9.1R9. It is, therefore, affected by multiple vulnerabilities:

  - A vulnerability in the Pulse Connect Secure < 9.1R9 admin web interface could allow an authenticated
    attacker to perform an arbitrary code execution using uncontrolled gzip extraction. (CVE-2020-8260)

  - A vulnerability in the Pulse Connect Secure / Pulse Policy Secure < 9.1R9 is vulnerable to arbitrary
    cookie injection. (CVE-2020-8261)

  - jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true,
    {}, ...) because of Object.prototype pollution. If an unsanitized source object contained an enumerable
    __proto__ property, it could extend the native Object.prototype. (CVE-2019-11358)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44601");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pulse Connect Secure version 9.1R9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8260");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Pulse Secure VPN gzip RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulsesecure:pulse_connect_secure");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pulse_connect_secure_detect.nbin");
  script_require_keys("installed_sw/Pulse Connect Secure");

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('vcf_extras.inc');

port = get_http_port(default:443, embedded:TRUE);
app_info = vcf::pulse_connect_secure::get_app_info(app:'Pulse Connect Secure', port:port, full_version:TRUE, webapp:TRUE);

# full ver from https://www-prev.pulsesecure.net/techpubs/pulse-connect-secure/pcs/9.1rx/9.1r9
constraints = [
 {'fixed_version':'9.1.9.9189', 'fixed_display':'9.1R9'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);

