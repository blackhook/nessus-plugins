#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49953);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/05");

  script_cve_id("CVE-2010-1883");
  script_bugtraq_id(43775);
  script_xref(name:"IAVA", value:"2010-A-0135-S");
  script_xref(name:"MSFT", value:"MS10-076");
  script_xref(name:"MSKB", value:"982132");

  script_name(english:"MS10-076: Vulnerability in the Embedded OpenType Font Engine Could Allow Remote Code Execution (982132)");
  script_summary(english:"Checks version of T2embed.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"It is possible to execute arbitrary code on the remote Windows host
using the Embedded OpenType Font Engine."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host contains a version of the Embedded OpenType
(EOT) Font Engine that is affected by an integer overflow
vulnerability when parsing certain tables within specially crafted
files and content containing embedded fonts.

If an attacker can trick a user on the affected system into viewing
content rendered in a specially crafted EOT font, this issue could be
leveraged to execute arbitrary code subject to the user's privileges."
  );
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2010/ms10-076
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?10312b23");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-1883");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS10-076';
kbs = make_list("982132");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = "982132";
if (
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1",                   file:"T2embed.dll", version:"6.1.7600.20788", min_version:"6.1.7600.20000", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1",                   file:"T2embed.dll", version:"6.1.7600.16663",                               dir:"\System32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"T2embed.dll", version:"6.0.6002.22475", min_version:"6.0.6002.20000", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"T2embed.dll", version:"6.0.6002.18301",                               dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"T2embed.dll", version:"6.0.6001.22750", min_version:"6.0.6001.22000", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"T2embed.dll", version:"6.0.6001.18520",                               dir:"\System32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 and XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"T2embed.dll", version:"5.2.3790.4766",                                dir:"\System32", bulletin:bulletin, kb:kb) ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"T2embed.dll", version:"5.1.2600.6031",                                dir:"\System32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/MS10-076", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
