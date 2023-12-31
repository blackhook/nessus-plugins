#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16324);
 script_version("1.35");
 script_cvs_date("Date: 2018/11/15 20:50:29");

 script_cve_id("CVE-2005-0053");
 script_bugtraq_id(11466);
 script_xref(name:"MSFT", value:"MS05-008");
 script_xref(name:"CERT", value:"698835");
 script_xref(name:"EDB-ID", value:"24693");
 script_xref(name:"MSKB", value:"890047");

 script_name(english:"MS05-008: Vulnerability in Windows Shell (890047)");
 script_summary(english:"Determines if hotfix 890047 has been installed");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the Windows Shell that
could allow an attacker to elevate his privileges and/or execute
arbitrary code on the remote host.

To exploit this flaw, an attacker would need to lure a victim into
visiting a malicious website or opening a malicious file attachment.");
 script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2005/ms05-008");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/20");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/02/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/08");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2018 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS05-008';
kb = '890047';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'3,4', xp:'1,2', win2003:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"Shell32.dll", version:"6.0.3790.241", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:1, file:"Shell32.dll", version:"6.0.2800.1613", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Shell32.dll", version:"6.0.2900.2578", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Shell32.dll", version:"5.0.3900.7009", dir:"\system32", bulletin:bulletin, kb:kb)
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
