#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171789);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/27");

  script_cve_id("CVE-2023-20858");
  script_xref(name:"VMSA", value:"2023-0004");
  script_xref(name:"IAVA", value:"2023-A-0111");

  script_name(english:"VMware Carbon Black App Control 8.7 < 8.7.8 / 8.8 < 8.8.6 / 8.9 < 8.9.4 Injection (VMSA-2023-0004)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"VMware Carbon Black App Control management server is affected by an injection vulnerability. A malicious actor with
privileged access to the App Control administration console may be able to use specially crafted input allowing access
to the underlying server operating system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2023-0004.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Carbon Black App Control 8.7,8, 8.8.6, 8.9.4 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20858");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/22");

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
  { 'min_version' : '8.7', 'fixed_version' : '8.7.8' },
  { 'min_version' : '8.8', 'fixed_version' : '8.8.6' },
  { 'min_version' : '8.9', 'fixed_version' : '8.9.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

