#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(35070);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2008-2249", "CVE-2008-3465");
  script_bugtraq_id(32634, 32637);
  script_xref(name:"MSFT", value:"MS08-071");
  script_xref(name:"MSKB", value:"956802");

  script_name(english:"MS08-071: Vulnerabilities in GDI+ Could Allow Remote Code Execution (956802)");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the Microsoft
GDI rendering engine.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows that is affected by
multiple buffer oveflow vulnerabilities when viewing WMF files, that
could allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, an attacker would need to send a malformed WMF
file to a user on the remote host and wait for him to open it using an
affected Microsoft application.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2008/ms08-071");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2008-2022 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "mssql_version.nasl", "smb_nt_ms02-031.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-071';
kb = '956802';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'1,2', vista:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# Windows 2000, XP, 2003, Vista, 2008 and IE 6
if (
  hotfix_is_vulnerable(os:"6.0", file:"Gdi32.dll", version:"6.0.6002.20609", min_version:"6.0.6002.0",dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Gdi32.dll", version:"6.0.6001.18159", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Gdi32.dll", version:"6.0.6000.16766", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.2", sp:1, file:"Gdi32.dll", version:"5.2.3790.3233", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Gdi32.dll", version:"5.2.3790.4396", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Gdi32.dll", version:"5.1.2600.3466", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Gdi32.dll", version:"5.1.2600.5698", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.0", file:"Gdi32.dll", version:"5.0.2195.7205", dir:"\system32", bulletin:bulletin, kb:kb)
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
