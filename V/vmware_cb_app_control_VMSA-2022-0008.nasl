##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162736);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/24");

  script_cve_id("CVE-2022-22951", "CVE-2022-22952");
  script_xref(name:"VMSA", value:"2022-0008");
  script_xref(name:"IAVA", value:"2022-A-0259-S");

  script_name(english:"VMware Carbon Black App Control 8.5.x < 8.5.14 / 8.6.x < 8.6.6 / 8.7 < 8.7.4 / 8.8 < 8.8.2 Multiple Vulnerabilities (VMSA-2022-0008)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities exist in the VMware Carbon Black App Control management server, as follows:

  - VMware Carbon Black App Control (8.5.x prior to 8.5.14, 8.6.x prior to 8.6.6, 8.7.x prior to 8.7.4 and
    8.8.x prior to 8.8.2) contains an OS command injection vulnerability. An authenticated, high privileged
    malicious actor with network access to the VMware App Control administration interface may be able to
    execute commands on the server due to improper input validation leading to remote code execution.
    (CVE-2022-22951)

  - VMware Carbon Black App Control (8.5.x prior to 8.5.14, 8.6.x prior to 8.6.6, 8.7.x prior to 8.7.4 and
    8.8.x prior to 8.8.2) contains a file upload vulnerability. A malicious actor with administrative access
    to the VMware App Control administration interface may be able to execute code on the Windows instance
    where AppC Server is installed by uploading a specially crafted file. (CVE-2022-22952)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-0008.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Carbon Black App Control 8.5.14, 8.6.6, 8.7.4, 8.8.2 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22952");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:carbon_black_app_control");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "vmware_carbon_black_app_control_win_installed.nbin", "vmware_carbon_black_app_control_web_console_detect.nbin");
  script_require_keys("installed_sw/VMware Carbon Black App Control");

  exit(0);
}

include('vcf.inc');

var app_name = 'VMware Carbon Black App Control';

# confirm the asset is windows 
var local_os = get_kb_item('Host/OS');
var reg_enum = get_kb_item('SMB/Registry/Enumerated');
if ((!empty_or_null(local_os) && 'windows' >!< tolower(local_os)) && !reg_enum )
  audit(AUDIT_OS_NOT, 'Windows');

var app_info = vcf::combined_get_app_info(app:app_name);
var constraints = [
  { 'min_version' : '8.5', 'fixed_version' : '8.5.14' },
  { 'min_version' : '8.6', 'fixed_version' : '8.6.6' },
  { 'min_version' : '8.7', 'fixed_version' : '8.7.4' },
  { 'min_version' : '8.8', 'fixed_version' : '8.8.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

