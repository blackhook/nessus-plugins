#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164652);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/25");

  script_cve_id(
    "CVE-2020-4301",
    "CVE-2020-28469",
    "CVE-2020-36518",
    "CVE-2021-3749",
    "CVE-2021-3807",
    "CVE-2021-20468",
    "CVE-2021-23438",
    "CVE-2021-28918",
    "CVE-2021-29418",
    "CVE-2021-29823",
    "CVE-2021-39009",
    "CVE-2021-39045",
    "CVE-2021-43797",
    "CVE-2021-44531",
    "CVE-2021-44532",
    "CVE-2021-44533",
    "CVE-2022-21803",
    "CVE-2022-21824",
    "CVE-2022-29078",
    "CVE-2022-30614",
    "CVE-2022-36773"
  );
  script_xref(name:"IAVB", value:"2022-B-0031-S");

  script_name(english:"IBM Cognos Analytics Multiple Vulnerabilities (6616285)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Cognos Analytics installed on the remote host is affected by multiple vulnerabilities, including the
following:

  - The ejs (aka Embedded JavaScript templates) package 3.1.6 for Node.js allows server-side template
    injection in settings[view options][outputFunctionName]. This is parsed as an internal option, and
    overwrites the outputFunctionName option with an arbitrary OS command (which is executed upon template
    compilation). (CVE-2022-29078)

  - The netmask package before 2.0.1 for Node.js mishandles certain unexpected characters in an IP address
    string, such as an octal digit of 9. This (in some situations) allows attackers to bypass access control
    that is based on IP addresses. NOTE: this issue exists because of an incomplete fix for CVE-2021-28918.
    (CVE-2021-29418)

  - Improper input validation of octal strings in netmask npm package v1.0.6 and below allows unauthenticated
    remote attackers to perform indeterminate SSRF, RFI, and LFI attacks on many of the dependent packages. A
    remote unauthenticated attacker can bypass packages relying on netmask to filter IPs and reach critical
    VPN or LAN hosts. (CVE-2021-28918)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6615285");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Cognos Analytics 11.1.7 FP5, 11.2.3, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29078");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:cognos_analytics");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_cognos_analytics_web_detect.nbin");
  script_require_keys("installed_sw/IBM Cognos Analytics");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'IBM Cognos Analytics';

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

# Remote detection cannot determine fix pack
if (app_info.version =~ "^11\.1\.7($|[^0-9])" && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, app_info['version'], app);

var constraints = [
  { 'min_version':'11.1', 'fixed_version':'11.1.8', 'fixed_display':'11.1.7 FP5' },
  { 'min_version':'11.2', 'fixed_version':'11.2.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
