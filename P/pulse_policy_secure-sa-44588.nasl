##
# (c) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141360);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-8238", "CVE-2020-8243", "CVE-2020-8256");
  script_xref(name:"IAVA", value:"2020-A-0444-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/04/23");

  script_name(english:"Pulse Policy Secure < 9.1R8.2 (SA44588)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Pulse Policy Secure running on the remote host is prior to
9.1R8.2. It is, therefore, affected by the following vulnerabilities:

  -  A vulnerability in the Pulse Connect Secure < 9.1R8.2 admin web interface could allow an authenticated
     attacker to upload custom template to perform an arbitrary code execution. (CVE-2020-8243)

  - A vulnerability in the authenticated user web interface of Pulse Connect Secure and Pulse Policy Secure <
    9.1R8.2 could allow attackers to conduct Cross-Site Scripting (XSS). (CVE-2020-8238)

  - A vulnerability in the Pulse Connect Secure < 9.1R8.2 admin web interface could allow an authenticated
    attacker to gain arbitrary file reading access through Pulse Collaboration via XML External Entity (XXE)
    vulnerability. (CVE-2020-8256)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44588/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2cb5f3ae");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pulse Policy Secure version 9.1R8.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8243");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulsesecure:pulse_policy_secure");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pulse_policy_secure_detect.nbin");
  script_require_keys("installed_sw/Pulse Policy Secure");

  exit(0);
}

include('vcf.inc');
include('http.inc');
include('vcf_extras.inc');

port = get_http_port(default:443, embedded:TRUE);
app_info = vcf::pulse_connect_secure::get_app_info(app:'Pulse Policy Secure', port:port, full_version:TRUE);

constraints = [
 {'fixed_version':'9.1.8.4187', 'fixed_display':'9.1R8.2'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);

