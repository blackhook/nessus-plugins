#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(33136);
 script_version("1.26");
 script_cvs_date("Date: 2018/11/15 20:50:30");

 script_cve_id("CVE-2008-1451");
 script_bugtraq_id(29588);
 script_xref(name:"MSFT", value:"MS08-034");
 script_xref(name:"MSKB", value:"948745");

 script_name(english:"MS08-034: Vulnerability in WINS Could Allow Elevation of Privilege (948745)");
 script_summary(english:"Checks the remote host for MS08-034");

 script_set_attribute(attribute:"synopsis", value:
"The remote WINS service can be abused to escalate privileges.");
 script_set_attribute(attribute:"description", value:
"The remote Windows Internet Naming Service (WINS) is vulnerable to a
memory overwrite attack that could allow a local attacker to elevate his
privileges on the remote host.");
 script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2008/ms08-034");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 2000 and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(20);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/06/10");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/06/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2018 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-034';
kb = '948745';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', win2003:'1,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if ( hotfix_check_wins_installed() <= 0 ) audit(AUDIT_NOT_INST, "WINS");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"Wins.exe", version:"5.2.3790.3119", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Wins.exe", version:"5.2.3790.4271", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.0", file:"Wins.exe", version:"5.0.2195.7155", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
