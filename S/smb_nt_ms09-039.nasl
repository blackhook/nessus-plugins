#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40558);
  script_version("1.26");
  script_cvs_date("Date: 2018/11/15 20:50:30");

  script_cve_id("CVE-2009-1923", "CVE-2009-1924");
  script_bugtraq_id(35980, 35981);
  script_xref(name:"MSFT", value:"MS09-039");
  script_xref(name:"MSKB", value:"969883");

  script_name(english:"MS09-039: Vulnerabilities in WINS Could Allow Remote Code Execution (969883)");
  script_summary(english:"Determines the presence of update 969883");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the WINS
service.");
  script_set_attribute(attribute:"description", value:
"The remote host has a Windows WINS server installed.

The remote version of this server contains two vulnerabilities that may
allow an attacker to execute arbitrary code on the remote system :

  - A heap overflow vulnerability can be exploited by any
    attacker.

  - A integer overflow vulnerability can be exploited by a
    WINS replication partner.

An attacker may use these flaws to execute arbitrary code on the remote
system with SYSTEM privileges.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2009/ms09-039");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000 and 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2018 Tenable Network Security, Inc.");

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

bulletin = 'MS09-039';
kb = '969883';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', win2003:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (!get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/WINS/DisplayName")) exit(0, "The host is not operate as a WINS server.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows Server 2003
  hotfix_is_vulnerable(os:"5.2", file:"Wins.exe", version:"5.2.3790.4520", dir:"\System32", bulletin:bulletin, kb:kb) ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0", file:"Wins.exe", version:"5.0.2195.7300", dir:"\System32", bulletin:bulletin, kb:kb)
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
