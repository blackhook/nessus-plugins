##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146581);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/18");

  script_cve_id("CVE-2021-1366");
  script_xref(name:"CISCO-SA", value:"cisco-sa-anyconnect-dll-hijac-JrcTOQMC");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv64243");
  script_xref(name:"IAVA", value:"2021-A-0096-S");

  script_name(english:"Cisco AnyConnect Secure Mobility Client for Windows with VPN Posture (HostScan) Module DLL Hijacking Vulnerability (cisco-sa-anyconnect-dll-hijac-JrcTOQMC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-anyconnect-dll-hijac-JrcTOQMC)");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the cisco-sa-anyconnect-dll-hijac-JrcTOQMC advisory.

  - A vulnerability in the interprocess communication (IPC) channel of Cisco AnyConnect Secure Mobility Client
    for Windows could allow an authenticated, local attacker to perform a DLL hijacking attack on an affected
    device if the VPN Posture (HostScan) Module is installed on the AnyConnect client. This vulnerability is
    due to insufficient validation of resources that are loaded by the application at run time. An attacker
    could exploit this vulnerability by sending a crafted IPC message to the AnyConnect process. A successful
    exploit could allow the attacker to execute arbitrary code on the affected machine with SYSTEM privileges.
    To exploit this vulnerability, the attacker needs valid credentials on the Windows system. (CVE-2021-1366)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-anyconnect-dll-hijac-JrcTOQMC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b2515a5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv64243");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv64243");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1366");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(347);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_anyconnect_vpn_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');
include('smb_hotfixes_fcheck.inc');

var app_info = vcf::get_app_info(app:'Cisco AnyConnect Secure Mobility Client', win_local:TRUE);

var hostscan_installed = FALSE;

var uninstall_entry = hotfix_displayname_in_uninstall_key(pattern:'Cisco AnyConnect Posture Module');
if (!empty_or_null(uninstall_entry))
{
  var path_key = str_replace(string:uninstall_entry, find:'DisplayName', replace:'InstallLocation');
  var hostscan_path = get_kb_item(path_key);
  if (!empty_or_null(hostscan_path))
  {
    var exe_path = hotfix_append_path(path:hostscan_path, value:"bin\cscan.exe");
    hotfix_check_fversion_init();
    if (hotfix_file_exists(path:exe_path))
      hostscan_installed = TRUE;
    hotfix_check_fversion_end();
  }
}

if (!hostscan_installed)
  audit(AUDIT_NOT_INST, 'Cisco HostScan (Cisco AnyConnect Posture Module)');

vcf::check_granularity(app_info:app_info, sig_segments:3);
var constraints = [
  { 'fixed_version' : '4.9.05042.0', 'fixed_display' : 'See vendor advisory' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
