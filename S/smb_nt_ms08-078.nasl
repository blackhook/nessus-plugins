#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(35221);
 script_version("1.31");
 script_cvs_date("Date: 2018/11/15 20:50:30");

 script_cve_id("CVE-2008-4844");
 script_bugtraq_id(32721);
 script_xref(name:"CERT", value:"493881");
 script_xref(name:"MSFT", value:"MS08-078");
 script_xref(name:"MSKB", value:"960714");

 script_name(english:"MS08-078: Microsoft Internet Explorer Security Update (960714)");
 script_summary(english:"Determines the presence of update 960714");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client.");
 script_set_attribute(attribute:"description", value:
"The remote host is missing the IE security update 960714.

The remote version of IE is vulnerable to a memory corruption which may
allow an attacker to execute arbitrary code on the remote host.");
 script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2008/ms08-078");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS08-078 Microsoft Internet Explorer Data Binding Memory Corruption');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/12/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/12/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/17");

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

bulletin = 'MS08-078';
kb = '960714';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'1,2', vista:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"6.0", file:"Mshtml.dll", version:"8.0.6001.22342", min_version:"8.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", file:"Mshtml.dll", version:"8.0.6001.18247", min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Mshtml.dll", version:"7.0.6001.22328", min_version:"7.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Mshtml.dll", version:"7.0.6001.18183", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.20973", min_version:"7.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.16788", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.2", sp:1, file:"Mshtml.dll", version:"6.0.3790.3261", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.4426", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", file:"Mshtml.dll", version:"8.0.6001.22342", min_version:"8.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", file:"Mshtml.dll", version:"8.0.6001.18247", min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", file:"Mshtml.dll", version:"7.0.6000.20973", min_version:"7.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", file:"Mshtml.dll", version:"7.0.6000.16788", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.1", file:"Mshtml.dll", version:"8.0.6001.22342", min_version:"8.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", file:"Mshtml.dll", version:"8.0.6001.18247", min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", file:"Mshtml.dll", version:"7.0.6000.20973", min_version:"7.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", file:"Mshtml.dll", version:"7.0.6000.16788", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mshtml.dll", version:"6.0.2900.5726", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.3492", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.0", file:"Mshtml.dll", version:"6.0.2800.1619", min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Mshtml.dll", version:"5.0.3872.1000", dir:"\system32", bulletin:bulletin, kb:kb)
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
