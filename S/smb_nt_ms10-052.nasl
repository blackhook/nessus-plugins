#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48289);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/05");

  script_cve_id("CVE-2010-1882");
  script_bugtraq_id(42298);
  script_xref(name:"IAVA", value:"2010-A-0107-S");
  script_xref(name:"MSFT", value:"MS10-052");
  script_xref(name:"MSKB", value:"2115168");

  script_name(english:"MS10-052: Vulnerability in Microsoft MPEG Layer-3 Codecs Could Allow Remote Code Execution (2115168)");
  script_summary(english:"Checks the version of L3codecx.ax");

  script_set_attribute(attribute:"synopsis", value:
"An audio codec on the remote Windows host has a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The MPEG Layer-3 Audio Codec for Microsoft DirectShow (l3codecx.ax),
which is distributed as part of Windows Media as well as the Windows
operating system, contains a buffer overflow vulnerability that can be
triggered by a specially crafted MPEG Layer-3 audio stream.

If an attacker can trick a user on the affected system into opening a
specially crafted media file or receiving specially crafted web
content, this issue could be leveraged to execute arbitrary code
subject to the user's privileges.");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2010/ms10-052
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?5269ddd3");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP and 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-1882");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

bulletin = 'MS10-052';
kbs = make_list("2115168");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = '2115168';
if (
  # Windows 2003 x64 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"L3codecx.ax", version:"1.6.0.52", dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||

  # Windows 2003 x86
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"L3codecx.ax", version:"1.6.0.52", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"L3codecx.ax", version:"1.6.0.52", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/MS10-052", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
