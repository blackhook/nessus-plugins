#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25023);
 script_version("1.37");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/05");

  script_cve_id("CVE-2007-1205");
 script_bugtraq_id(23337);
 script_xref(name:"MSFT", value:"MS07-020");
 script_xref(name:"MSKB", value:"932168");
 
 script_xref(name:"IAVA", value:"2007-A-0021-S");
 script_xref(name:"CERT", value:"728057");

 script_name(english:"MS07-020: Vulnerability in Microsoft Agent Could Allow Remote Code Execution (932168)");
 script_summary(english:"Determines the presence of update 932168");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web or
email client.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the Microsoft Agent
service that could allow an attacker to execute code on the remote host.

To exploit this flaw, an attacker would need to set up a rogue website
and lure a victim on the remote host into visiting it.");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2007/ms07-020
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?8daebe81");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and
Vista.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-1205");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/10");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/04/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"stig_severity", value:"II");
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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS07-020';
kb = "932168";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2', win2003:'0,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);


if (
  hotfix_is_vulnerable(os:"5.2", sp:0, arch:"x86", file:"Agentdpv.dll", version:"2.0.0.3425", dir:"\msagent", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:1, arch:"x86", file:"Agentdpv.dll", version:"5.2.3790.1243", dir:"\msagent", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"Agentdpv.dll", version:"5.2.3790.1243", dir:"\msagent", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Agentdpv.dll", version:"2.0.0.3425", dir:"\msagent", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.0", file:"Agentdpv.dll", version:"2.0.0.3425", dir:"\msagent", bulletin:bulletin, kb:kb)
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
