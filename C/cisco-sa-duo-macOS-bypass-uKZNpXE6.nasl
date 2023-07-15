#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166791);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/28");

  script_cve_id("CVE-2022-20662");

  script_name(english:"Cisco Duo for macOS Authentication Bypass (cisco-sa-duo-macOS-bypass-uKZNpXE6)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the smart card login authentication of Cisco Duo for macOS could allow an unauthenticated attacker
with physical access to bypass authentication. This vulnerability exists because the assigned user of a smart card is
not properly matched with the authenticating user. An attacker could exploit this vulnerability by configuring a smart
card login to bypass Duo authentication. A successful exploit could allow the attacker to use any personal identity
verification (PIV) smart card for authentication, even if the smart card is not assigned to the authenticating user.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-duo-macOS-bypass-uKZNpXE6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a57516c2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Duo version 2.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20662");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:duo");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macos_cisco_duo_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Cisco Duo");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version')) audit(AUDIT_OS_NOT, 'macOS / Mac OS X');

var app = 'Cisco Duo';
var app_info = vcf::get_app_info(app:app);

var fixed_version = '2.0.0';

# Cannot check to see if smart card authentication is enabled
if (report_paranoia < 2 && ver_compare(ver:app_info.version, fix:fixed_version, strict:FALSE) < 0)
  audit(AUDIT_POTENTIAL_VULN, app, app_info.version);

var constraints = [
  { 'fixed_version' : fixed_version }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
