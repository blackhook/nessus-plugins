#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(24333);
 script_version("1.32");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/05");

  script_cve_id("CVE-2006-5559");
 script_bugtraq_id(20704);
 script_xref(name:"MSFT", value:"MS07-009");
 script_xref(name:"MSKB", value:"927779");
 
 script_xref(name:"IAVA", value:"2007-A-0015-S");
 script_xref(name:"CERT", value:"589272");
 script_xref(name:"EDB-ID", value:"2629");

 script_name(english:"MS07-009: Vulnerability in Microsoft Data Access Components Could Allow Remote Code Execution (927779)");
 script_summary(english:"Checks the version of MDAC");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the ADODB.Connection ActiveX
control that is vulnerable to a security flaw that could allow an
attacker to execute arbitrary code on the remote host by constructing a
malicious web page and entice a victim to visit this web page.");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2007/ms07-009
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?8c0aa61d");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-5559");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/27");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/02/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:data_access_components");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2007-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS07-009';
kb = "927779";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2', win2003:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

path = hotfix_get_commonfilesdir();
if (!path) exit(1, "Filed to get the Common Files directory.");
path += '\\system\\ado\\';

share = hotfix_path2share(path:path);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"msado15.dll", version:"2.80.1064.0", path:path, bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.1", sp:2, file:"msado15.dll", version:"2.81.1128.0", path:path, bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.0", file:"msado15.dll", version:"2.71.9054.0", min_version:"2.71.0.0", path:path, bulletin:bulletin, kb:kb)  ||
  hotfix_is_vulnerable(os:"5.0", file:"msado15.dll", version:"2.80.1064.0", min_version:"2.80.0.0", path:path, bulletin:bulletin, kb:kb)  ||
  hotfix_is_vulnerable(os:"5.0", file:"msado15.dll", version:"2.81.1128.0", min_version:"2.81.0.0", path:path, bulletin:bulletin, kb:kb)  ||
  hotfix_is_vulnerable(os:"5.0", file:"msado15.dll", version:"2.53.6307.0", path:path, bulletin:bulletin, kb:kb)
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
