#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40561);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/05");

  script_cve_id("CVE-2009-1930");
  script_bugtraq_id(35993);
  script_xref(name:"MSFT", value:"MS09-042");
  script_xref(name:"MSKB", value:"960859");
  script_xref(name:"IAVB", value:"2009-B-0037-S");

  script_name(english:"MS09-042: Vulnerability in Telnet Could Allow Remote Code Execution (960859)");
  script_summary(english:"Checks version of Telnet.exe");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the remote
Telnet client.");
  script_set_attribute(attribute:"description", value:
"The remote Telnet client does not correctly opt in to NTLM credential-
reflection protections, which ensure that a user's credentials are not
reflected back and used against the user.

If a remote attacker can trick a user on the host into connecting to a
malicious server with an affected version of the Telnet client, he can
leverage this issue to gain the rights of that user and do anything that
he has privileges to do.");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2009/ms09-042
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?974a963b");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-1930");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(255);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS09-042';
kb = '960859';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'0,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Telnet.exe", version:"6.0.6002.22150", min_version:"6.0.6002.20000", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Telnet.exe", version:"6.0.6002.18049",                               dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Telnet.exe", version:"6.0.6001.22447", min_version:"6.0.6001.20000", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Telnet.exe", version:"6.0.6001.18270",                               dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Telnet.exe", version:"6.0.6000.21065", min_version:"6.0.6000.20000", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Telnet.exe", version:"6.0.6000.16868",                               dir:"\System32", bulletin:bulletin, kb:kb) ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Telnet.exe", version:"5.2.3790.4528", dir:"\System32", bulletin:bulletin, kb:kb) ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Telnet.exe", version:"5.1.2600.5829", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Telnet.exe", version:"5.2.3790.4528", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Telnet.exe", version:"5.1.2600.3587", dir:"\System32", bulletin:bulletin, kb:kb) ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",                   file:"Telnet.exe", version:"5.0.33670.4", dir:"\System32", bulletin:bulletin, kb:kb)
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
