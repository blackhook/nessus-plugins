#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45506);
  script_version("1.24");
  script_cvs_date("Date: 2018/11/15 20:50:30");

  script_cve_id("CVE-2010-0486", "CVE-2010-0487");
  script_bugtraq_id(39328, 39332);
  script_xref(name:"MSFT", value:"MS10-019");
  script_xref(name:"MSKB", value:"978601");
  script_xref(name:"MSKB", value:"979309");

  script_name(english:"MS10-019: Vulnerabilities in Windows Could Allow Remote Code Execution (981210)");
  script_summary(english:"Checks the versions of wintrust.dll and cabview.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Windows host has multiple code execution vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Windows running on the remote host has vulnerabilities
in the Windows Authenticode Signature mechanism.  Modifying an
existing signed executable or cabinet file can result in arbitrary
code execution.

A remote attacker could exploit this by tricking a user into executing
or opening a maliciously crafted file, resulting in arbitrary code
execution."
  );
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2010/ms10-019");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista, 2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2018 Tenable Network Security, Inc.");

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

bulletin = 'MS10-019';
kbs = make_list("978601","979309");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'0,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1",                   file:"Wintrust.dll", version:"6.1.7600.20605",  min_version:"6.1.7600.20000",  dir:"\system32", bulletin:bulletin, kb:"978601") ||
  hotfix_is_vulnerable(os:"6.1",                   file:"Wintrust.dll", version:"6.1.7600.16493",  min_version:"6.1.7600.16000",  dir:"\system32", bulletin:bulletin, kb:"978601") ||
  hotfix_is_vulnerable(os:"6.1",                   file:"Cabview.dll",  version:"6.1.7600.20613",  min_version:"6.1.7600.20000",  dir:"\system32", bulletin:bulletin, kb:"979309") ||
  hotfix_is_vulnerable(os:"6.1",                   file:"Cabview.dll",  version:"6.1.7600.16500",  min_version:"6.1.7600.16000",  dir:"\system32", bulletin:bulletin, kb:"979309") ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Wintrust.dll", version:"6.0.6002.22293",  min_version:"6.0.6002.22000",  dir:"\system32", bulletin:bulletin, kb:"978601") ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Wintrust.dll", version:"6.0.6002.18169",  min_version:"6.0.6001.18000",  dir:"\system32", bulletin:bulletin, kb:"978601") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Wintrust.dll", version:"6.0.6001.22588",  min_version:"6.0.6001.22000",  dir:"\system32", bulletin:bulletin, kb:"978601") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Wintrust.dll", version:"6.0.6001.18387",  min_version:"6.0.6001.18000",  dir:"\system32", bulletin:bulletin, kb:"978601") ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Wintrust.dll", version:"6.0.6000.21186",  min_version:"6.0.6000.20000",  dir:"\system32", bulletin:bulletin, kb:"978601") ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Wintrust.dll", version:"6.0.6000.16984",  min_version:"6.0.6000.16000",  dir:"\system32", bulletin:bulletin, kb:"978601") ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Cabview.dll",  version:"6.0.6002.22311",  min_version:"6.0.6002.22000",  dir:"\system32", bulletin:bulletin, kb:"979309") ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Cabview.dll",  version:"6.0.6002.18184",  min_version:"6.0.6001.18000",  dir:"\system32", bulletin:bulletin, kb:"979309") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Cabview.dll",  version:"6.0.6001.22605",  min_version:"6.0.6001.22000",  dir:"\system32", bulletin:bulletin, kb:"979309") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Cabview.dll",  version:"6.0.6001.18404",  min_version:"6.0.6001.18000",  dir:"\system32", bulletin:bulletin, kb:"979309") ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Cabview.dll",  version:"6.0.6000.21203",  min_version:"6.0.6000.20000",  dir:"\system32", bulletin:bulletin, kb:"979309") ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Cabview.dll",  version:"6.0.6000.17002",  min_version:"6.0.6000.16000",  dir:"\system32", bulletin:bulletin, kb:"979309") ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Wintrust.dll", version:"5.131.3790.4642",                                dir:"\system32", bulletin:bulletin, kb:"978601") ||
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Cabview.dll",  version:"6.0.3790.4649",                                  dir:"\system32", bulletin:bulletin, kb:"979309") ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wintrust.dll", version:"5.131.2600.5922", min_version:"5.131.2600.5000", dir:"\system32", bulletin:bulletin, kb:"978601") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Wintrust.dll", version:"5.131.2600.3661",                                dir:"\system32", bulletin:bulletin, kb:"978601") ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Cabview.dll",  version:"6.0.2900.5927",   min_version:"6.0.2900.5000",   dir:"\system32", bulletin:bulletin, kb:"979309") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Cabview.dll",  version:"6.0.2900.3663",                                  dir:"\system32", bulletin:bulletin, kb:"979309") ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",                   file:"Wintrust.dll", version:"5.131.2195.7375",                                dir:"\system32", bulletin:bulletin, kb:"978601") ||
  hotfix_is_vulnerable(os:"5.0",                   file:"Cabview.dll",  version:"5.0.3900.7369",                                  dir:"\system32", bulletin:bulletin, kb:"979309")
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
