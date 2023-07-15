#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171595);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/06");

  script_cve_id(
    "CVE-2023-23918",
    "CVE-2023-23919",
    "CVE-2023-23920",
    "CVE-2023-23936",
    "CVE-2023-24807"
  );
  script_xref(name:"IAVB", value:"2023-B-0013");

  script_name(english:"Node.js 14.x < 14.21.3 / 16.x < 16.19.1 / 18.x < 18.14.1 / 19.x < 19.6.1 Multiple Vulnerabilities (Thursday February 16 2023 Security Releases).");

  script_set_attribute(attribute:"synopsis", value:
"Node.js - JavaScript run-time environment is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Node.js installed on the remote host is prior to 14.21.3, 16.19.1, 18.14.1, 19.6.1. It is, therefore,
affected by multiple vulnerabilities as referenced in the Thursday February 16 2023 Security Releases advisory.

  - It was possible to bypass Permissions and access non authorized modules by using
    process.mainModule.require().  This only affects users who had enabled the experimental permissions option
    with --experimental-policy. Thank you, to @goums for reporting this vulnerability and thank you  Rafael
    Gonzaga for fixing it. Impacts: (CVE-2023-23918)

  - In some cases Node.js did does not clear the OpenSSL error stack after operations that may set it. This
    may lead to false positive errors during subsequent cryptographic operations that happen to be on the same
    thread. This in turn could be used to cause a denial of service. Thank you, to Morgan Jones and Ryan
    Dorrity from Viasat Secure Mobile for reporting and discovering this vulnerability and thank you Rafael
    Gonzaga for fixing it. Impacts: (CVE-2023-23919)

  - The fetch API in Node.js did not prevent CRLF injection in the 'host' header potentially allowing attacks
    such as HTTP response splitting and HTTP header injection. Thank you, to Zhipeng Zhang (@timon8) for
    reporting this vulnerability and thank you Robert Nagy for fixing it. Impacts: (CVE-2023-23936)

  - The Headers.set() and Headers.append() methods in the fetch API in Node.js where vulnerable to Regular a
    Expression Denial of Service (ReDoS) attacks. Thank you, to Carter Snook for reporting this vulnerability
    and thank you Rich Trott for fixing it. Impacts: (CVE-2023-24807)

  - Node.js would search and potentially load ICU data when running with elevated priviledges. Node.js was
    modified to build with ICU_NO_USER_DATA_OVERRIDE to avoid this. Thank you, to Ben Noordhuis for reporting
    this vulnerability and thank you  Rafael Gonzaga for fixing it. Impacts: (CVE-2023-23920)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://nodejs.org/en/blog/vulnerability/february-2023-security-releases/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?461376f3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Node.js version 14.21.3 / 16.19.1 / 18.14.1 / 19.6.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23918");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nodejs:node.js");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nodejs_win_installed.nbin", "macosx_nodejs_installed.nbin");
  script_require_keys("installed_sw/Node.js");

  exit(0);
}

include('vcf.inc');

var win_local = FALSE;
var os = get_kb_item_or_exit('Host/OS');
if ('windows' >< tolower(os)) win_local = TRUE;
var app_info = vcf::get_app_info(app:'Node.js', win_local:win_local);
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '14.0.0', 'fixed_version' : '14.21.3' },
  { 'min_version' : '16.0.0', 'fixed_version' : '16.19.1' },
  { 'min_version' : '18.0.0', 'fixed_version' : '18.14.1' },
  { 'min_version' : '19.0.0', 'fixed_version' : '19.6.1' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
