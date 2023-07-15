#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166390);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/22");

  script_cve_id("CVE-2022-34384", "CVE-2022-34389");
  script_xref(name:"IAVA", value:"2022-A-0423");

  script_name(english:"Dell SupportAssist Multiple Vulnerabilities (DSA-2022-190)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a Dell SupportAssist that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Dell SupportAssist Client is affected by multiple
vulnerabilities.

  - SupportAssist Client Consumer (version 3.11.1 and prior), SupportAssist Client Commercial (version 3.2 and
    prior), Dell Command | Update, Dell Update, and Alienware Update versions before 4.5 contain a Local
    Privilege Escalation Vulnerability in the Advanced Driver Restore component. A local malicious user may
    potentially exploit this vulnerability, leading to privilege escalation. (CVE-2022-34384)

  - Dell SupportAssist contains a rate limit bypass issues in screenmeet API third party component. An
    unauthenticated attacker could potentially exploit this vulnerability and impersonate a legitimate dell
    customer to a dell support technician. (CVE-2022-34389)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-ie/000204114/dsa-2022-190-dell-supportassist-for-home-and-business-pcs-security-update-for-multiple-proprietary-code-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd431590");
  script_set_attribute(attribute:"solution", value:
"Update Dell SupportAssist Client Consumer to version 3.12.3, Dell Client Commercial 3.3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34384");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:supportassist");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_supportassist_installed.nbin");
  script_require_keys("installed_sw/Dell SupportAssist");

  exit(0);
}
include('vcf.inc');

var app_info = vcf::get_app_info(app:'Dell SupportAssist', win_local:TRUE);
var dell_edition = tolower(app_info['Edition']);

if ('business' >< dell_edition)
  var constraints = [
    {'max_version':'3.2.0', 'fixed_version':'3.3.0'}
  ]; 
else constraints = [{'max_version':'3.11.2', 'fixed_version':'3.12.3'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
