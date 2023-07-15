#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(20005);
 script_version("1.50");
 script_cvs_date("Date: 2018/11/15 20:50:29");

 script_cve_id("CVE-2005-2127");
 script_bugtraq_id(14594, 15061);
 script_xref(name:"MSFT", value:"MS05-052");
 script_xref(name:"CERT", value:"740372");
 script_xref(name:"CERT", value:"898241");
 script_xref(name:"MSKB", value:"896688");

 script_name(english:"MS05-052: Cumulative Security Update for Internet Explorer (896688)");
 script_summary(english:"Determines the presence of update 896688");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Internet Explorer that is
vulnerable to a security flaw (COM Object Instantiation Memory
Corruption Vulnerability) that could allow an attacker to execute
arbitrary code on the remote host by constructing a malicious web page
and entice a victim to visit this web page.");
 script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2005/ms05-052");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP SP2 and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/17");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/10/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS05-052';
kb = '896688';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'1,2', win2003:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"Mshtml.dll", version:"6.0.3790.418", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"Mshtml.dll", version:"6.0.3790.2541", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.2769", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:1, file:"Mshtml.dll", version:"6.0.2800.1522", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Mshtml.dll", version:"6.0.2800.1522", min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Mshtml.dll", version:"5.0.3833.200", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  set_kb_item (name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Updates/KB896688", value:TRUE);
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}