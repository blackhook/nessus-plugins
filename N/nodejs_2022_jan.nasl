#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157354);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/04");

  script_cve_id(
    "CVE-2021-44531",
    "CVE-2021-44532",
    "CVE-2021-44533",
    "CVE-2022-21824"
  );
  script_xref(name:"IAVB", value:"2022-B-0002-S");

  script_name(english:"Node.js 12.x < 12.22.9 / 14.x < 14.18.3 / 16.x < 16.13.2 / 17.x < 17.3.1 Multiple Vulnerabilities (January 10th 2022 Security Releases).");

  script_set_attribute(attribute:"synopsis", value:
"Node.js - JavaScript run-time environment is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Node.js installed on the remote host is prior to 12.22.9, 14.18.3, 16.13.2, 17.3.1. It is, therefore,
affected by multiple vulnerabilities as referenced in the January 10th 2022 Security Releases advisory.

  - Accepting arbitrary Subject Alternative Name (SAN) types, unless a PKI is specifically defined to use a
    particular SAN type, can result in bypassing name-constrained intermediates. Node.js was accepting URI SAN
    types, which PKIs are often not defined to use. Additionally, when a protocol allows URI SANs, Node.js did
    not match the URI correctly. (CVE-2021-44531)

  - Node.js converts SANs (Subject Alternative Names) to a string format. It uses this string to check peer
    certificates against hostnames when validating connections. The string format was subject to an injection
    vulnerability when name constraints were used within a certificate chain, allowing the bypass of these
    name constraints. (CVE-2021-44532)

  - Node.js did not handle multi-value Relative Distinguished Names correctly. Attackers could craft
    certificate subjects containing a single-value Relative Distinguished Name that would be interpreted as a
    multi-value Relative Distinguished Name, for example, in order to inject a Common Name that would allow
    bypassing the certificate subject verification. (CVE-2021-44533)

  - Due to the formatting logic of the console.table() function it was not safe to allow user controlled input
    to be passed to the properties parameter while simultaneously passing a plain object with at least one
    property as the first parameter, which could be __proto__. The prototype pollution has very limited
    control, in that it only allows an empty string to be assigned to numerical keys of the object prototype.
    (CVE-2022-21824)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://nodejs.org/en/blog/vulnerability/jan-2022-security-releases/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Node.js version 12.22.9 / 14.18.3 / 16.13.2 / 17.3.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21824");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nodejs:node.js");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nodejs_win_installed.nbin");
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
  { 'min_version' : '12.0.0', 'fixed_version' : '12.22.9' },
  { 'min_version' : '14.0.0', 'fixed_version' : '14.18.3' },
  { 'min_version' : '16.0.0', 'fixed_version' : '16.13.2' },
  { 'min_version' : '17.0.0', 'fixed_version' : '17.3.1' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
