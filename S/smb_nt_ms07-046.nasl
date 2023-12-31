#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25884);
 script_version("1.30");
 script_cvs_date("Date: 2018/11/15 20:50:30");

 script_cve_id("CVE-2007-3034");
 script_bugtraq_id(25302);
 script_xref(name:"MSFT", value:"MS07-046");
 script_xref(name:"MSKB", value:"938829");
 
 script_xref(name:"CERT", value:"640136");

 script_name(english:"MS07-046: Vulnerability in GDI Could Allow Remote Code Execution (938829)");
 script_summary(english:"Determines the presence of update 938829");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host by sending a
malformed file to a victim.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Windows that has
several vulnerabilities in the Graphic Rendering Engine and in the way
Windows handles Metafiles.

An attacker may exploit these flaws to execute arbitrary code on the
remote host.  To exploit this flaw, an attacker would need to send a
specially crafted image to a user on the remote host, or lure him into
visiting a rogue website containing such a file.");
 script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2007/ms07-046");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and
Vista.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(189);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/08/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/14");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2018 Tenable Network Security, Inc.");
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

bulletin = 'MS07-046';
kb = '938829';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2', win2003:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"gdi32.dll", version:"5.2.3790.2960", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"gdi32.dll", version:"5.1.2600.3159", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0",       file:"gdi32.dll", version:"5.0.2195.7138", dir:"\system32", bulletin:bulletin, kb:kb)
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
