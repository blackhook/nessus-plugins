#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94012);
  script_version("1.15");
  script_cvs_date("Date: 2019/05/30 11:03:54");

  script_cve_id(
    "CVE-2016-3266",
    "CVE-2016-3341",
    "CVE-2016-3376",
    "CVE-2016-7185",
    "CVE-2016-7211"
  );
  script_bugtraq_id(
    93384,
    93388,
    93389,
    93391,
    93556
  );
  script_xref(name:"MSFT", value:"MS16-123");
  script_xref(name:"MSKB", value:"3191203");
  script_xref(name:"MSKB", value:"3183431");
  script_xref(name:"MSKB", value:"3192391");
  script_xref(name:"MSKB", value:"3185330");
  script_xref(name:"MSKB", value:"3192392");
  script_xref(name:"MSKB", value:"3185331");
  script_xref(name:"MSKB", value:"3192393");
  script_xref(name:"MSKB", value:"3185332");
  script_xref(name:"MSKB", value:"3192440");
  script_xref(name:"MSKB", value:"3192441");
  script_xref(name:"MSKB", value:"3194798");
  script_xref(name:"MSKB", value:"4038788");
  script_xref(name:"IAVA", value:"2016-A-0279");

  script_name(english:"MS16-123: Security Update for Windows Kernel-Mode Drivers (3192892)");
  script_summary(english:"Checks the version of ntoskrnl.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - Multiple elevation of privilege vulnerabilities exist in
    the Windows kernel-mode driver due to improper handling
    of objects in memory. A local attacker can exploit
    these, via a specially crafted application, to execute
    arbitrary code in kernel mode. (CVE-2016-3266,
    CVE-2016-3376, CVE-2016-7185, CVE-2016-7191)

  - An elevation of privilege vulnerability exists in
    Windows Transaction Manager due to improper handling of
    objects in memory. A local attacker can exploit this,
    via a specially crafted application, to execute
    processes in an elevated context. (CVE-2016-3341)");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-123
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e7e63f93");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3266");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");


  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "smb_check_rollup.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-123';
kbs = make_list(
  '3191203',
  '3183431',
  '3192391',
  '3185330',
  '3192392',
  '3185331',
  '3192393',
  '3185332',
  '3192440',
  '3192441',
  '3194798',
  '4038788'
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Windows 8 EOL
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.24017", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3191203") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.19693", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3191203") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mrxdav.sys", version:"6.0.6002.24016", min_version:"6.0.6002.23000", dir:"\system32\drivers", bulletin:bulletin, kb:"3183431") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mrxdav.sys", version:"6.0.6002.19691", min_version:"6.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:"3183431") ||
  # 8.1 / 2012 R2
  smb_check_rollup(os:"6.3",
                   sp:0,
                   rollup_date: "10_2016",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(3192392, 3185331)) ||
  # 2012
  smb_check_rollup(os:"6.2",
                   sp:0,
                   rollup_date: "10_2016",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(3192393, 3185332)) ||
  # 7 / 2008 R2
  smb_check_rollup(os:"6.1",
                   sp:1,
                   rollup_date: "10_2016",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(3185330, 3192391)) ||
  # 10 (1507)
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"10240",
                   rollup_date: "10_2016",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(3192440)) ||
  # 10 (1511)
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"10586",
                   rollup_date: "10_2016",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(3192441)) ||
  # 10 (1607)
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"14393",
                   rollup_date: "10_2016",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(3194798)) ||

  # 10 (1703)
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"15063",
                   rollup_date: "09_2017",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(4038788))
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
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
