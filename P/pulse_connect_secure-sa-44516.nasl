#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(139225);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-8204",
    "CVE-2020-8206",
    "CVE-2020-8216",
    "CVE-2020-8217",
    "CVE-2020-8218",
    "CVE-2020-8219",
    "CVE-2020-8220",
    "CVE-2020-8221",
    "CVE-2020-8222",
    "CVE-2020-12880",
    "CVE-2020-15408"
  );
  script_xref(name:"IAVA", value:"2020-A-0347-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/07");

  script_name(english:"Pulse Connect Secure < 9.1R8 (SA44516)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Pulse Connect Secure running on the remote host is prior 
to 9.1R8. It is, therefore, affected by multiple vulnerabilities:

- An attacker can bypass the Google TOTP, if the primary credentials are exposed to attacker (CVE-2020-8206).

- An authenticated attacker via the admin web interface can crafted URI to perform an arbitrary code execution 
(CVE-2020-8218).

- An authenticated attacker via the administrator web interface can read arbitrary files (CVE-2020-8221). 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44516
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f4f18332");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pulse Connect Secure version 9.1R8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8206");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/31");

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

# full ver from https://www-prev.pulsesecure.net/download/techpubs/current/2104/pulse-connect-secure/pcs/9.1rx/9.1r8/ps-pcs-sa-9.1r8.0-releasenotes.pdf
constraints = [
 {'fixed_version':'9.1.8.7453', 'fixed_display':'9.1R8'}
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

