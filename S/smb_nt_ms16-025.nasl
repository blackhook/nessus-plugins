#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89748);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2016-0100");
  script_bugtraq_id(83930);
  script_xref(name:"MSFT", value:"MS16-025");
  script_xref(name:"MSKB", value:"3140709");
  script_xref(name:"IAVA", value:"2016-A-0067");

  script_name(english:"MS16-025: Security Update for Windows Library Loading to Address Remote Code Execution (3140709)");
  script_summary(english:"Checks file version of wab.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a remote code execution
vulnerability due to improper validation of input before loading
certain libraries. An authenticated, remote attacker can exploit this,
via a specially crafted application, to execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-025");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista and 2008.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0100");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Office OLE Multiple DLL Side Loading Vulnerabilities');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-025';
kb = '3140709';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
installroot = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Windows Mail\InstallRoot");
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if (empty_or_null(installroot))
{
  hotfix_check_fversion_end();
  audit(AUDIT_NOT_INST, "Windows Mail");
}

path = str_replace(string:installroot, find:"%ProgramFiles%", replace: hotfix_get_programfilesdir());

share = hotfix_path2share(path:path);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"wab.exe", version:"6.0.6002.23910", min_version:"6.0.6002.20000", path: path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"wab.exe", version:"6.0.6002.19598", min_version:"6.0.6001.18000", path: path, bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
