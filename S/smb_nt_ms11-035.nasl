#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53858);
  script_version("1.17");
  script_cvs_date("Date: 2018/11/15 20:50:30");

  script_cve_id("CVE-2011-1248");
  script_bugtraq_id(47730);
  script_xref(name:"EDB-ID", value:"17830");
  script_xref(name:"MSFT", value:"MS11-035");
  script_xref(name:"MSKB", value:"2524426");

  script_name(english:"MS11-035: Vulnerability in WINS Could Allow Remote Code Execution (2524426)");
  script_summary(english:"Checks the file version of wins.exe.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through Microsoft
Windows Internet Name Service (WINS)."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of WINS (Windows Internet Name Service) installed on the
remote Windows host is affected by a memory corruption vulnerability due
to a logic error when handling a socket send exception.

By sending specially crafted packets to the affected WINS system, a
remote attacker can potentially exploit this issue to execute arbitrary
code as either SYSTEM on Windows 2003 or Local Service on Windows 2008 /
2008 R2.

Note that WINS is not installed by default on any of the affected
operating systems, although Nessus has determined it is on this host."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-167/");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2011/ms11-035");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows 2003, 2008, and
2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");

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

bulletin = 'MS11-035';
kb = '2524426';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'1,2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if ( ! get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/WINS/DisplayName") )
  exit(0, "The host is not running WINS and is therefore not affected.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows Server 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Wins.exe", version:"5.2.3790.4849", dir:"\System32", bulletin:bulletin, kb:kb) ||

  # Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Wins.exe", version:"6.0.6001.18629", min_version:"6.0.6001.18000", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Wins.exe", version:"6.0.6001.22891", min_version:"6.0.6001.22000", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Wins.exe", version:"6.0.6002.18441", min_version:"6.0.6001.18000", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Wins.exe", version:"6.0.6002.22621", min_version:"6.0.6002.22000", dir:"\System32", bulletin:bulletin, kb:kb) ||

  # Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Wins.exe", version:"6.1.7600.16788", min_version:"6.1.7600.16000", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Wins.exe", version:"6.1.7600.20934", min_version:"6.1.7600.20000", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Wins.exe", version:"6.1.7601.17586", min_version:"6.1.7600.17000", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Wins.exe", version:"6.1.7601.21692", min_version:"6.1.7601.21000", dir:"\System32", bulletin:bulletin, kb:kb)
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
