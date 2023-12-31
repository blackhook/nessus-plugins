#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95813);
  script_version("1.8");
  script_cvs_date("Date: 2018/11/15 20:50:32");

  script_cve_id(
    "CVE-2016-7219",
    "CVE-2016-7292"
  );
  script_bugtraq_id(
    94764,
    94768
  );
  script_xref(name:"MSFT", value:"MS16-149");
  script_xref(name:"MSKB", value:"3204808");
  script_xref(name:"MSKB", value:"3196726");
  script_xref(name:"MSKB", value:"3205394");
  script_xref(name:"MSKB", value:"3207752");
  script_xref(name:"MSKB", value:"3205408");
  script_xref(name:"MSKB", value:"3205409");
  script_xref(name:"MSKB", value:"3205400");
  script_xref(name:"MSKB", value:"3205401");
  script_xref(name:"MSKB", value:"3205383");
  script_xref(name:"MSKB", value:"3205386");
  script_xref(name:"MSKB", value:"3206632");
  script_xref(name:"IAVA", value:"2016-A-0350");

  script_name(english:"MS16-149: Security Update for Microsoft Windows (3205655)");
  script_summary(english:"Checks the file versions and rollups.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists in a
    Windows Crypto driver running in kernel mode due to
    improper handling of objects in memory. A local attacker
    can exploit this, via a specially crafted application,
    to disclose sensitive information. (CVE-2016-7219)

  - An elevation of privilege vulnerability exists in the
    Windows installer due to improper sanitization of input,
    leading to insecure library loading behavior. A local
    attacker can exploit this to run arbitrary code with
    elevated system privileges. (CVE-2016-7292)");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-149");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, 10, and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/11/17");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/14");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2018 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "smb_check_rollup.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}
include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-149';

kbs = make_list('3204808',
                '3196726',
                '3205394',
                '3207752',
                '3205408',
                '3205409',
                '3205400',
                '3205401',
                '3205383',
                '3205386',
                '3206632');

if (get_kb_item("Host/patch_management_checks")) 
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
# Windows 8 EOL
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"msi.dll", version:"4.5.6002.24034", min_version:"4.5.6002.20000", dir:"\system32", bulletin:bulletin, kb:"3196726") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"msi.dll", version:"4.5.6002.19712", min_version:"4.5.6002.16000", dir:"\system32", bulletin:bulletin, kb:"3196726") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"bcrypt.dll", version:"6.0.6002.24042", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"3204808") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"bcrypt.dll", version:"6.0.6002.19720", min_version:"6.0.6002.00000", dir:"\system32", bulletin:bulletin, kb:"3204808") ||
  # Windows 7 / Server 2008 R2 # security: 3205394, monthly: 3207752
  smb_check_rollup(os:"6.1", sp:1, rollup_date:"12_2016", bulletin:bulletin, rollup_kb_list:make_list(3205394, 3207752)) ||
  # Windows Server 2012 # security: 3205408, monthly: 325409
  smb_check_rollup(os:"6.2", sp:0, rollup_date:"12_2016", bulletin:bulletin, rollup_kb_list:make_list(3205408, 3205409)) ||
  # Windows 8.1 / Windows Server 2012 R2
  smb_check_rollup(os:"6.3", sp:0, rollup_date:"12_2016", bulletin:bulletin, rollup_kb_list:make_list(3205400, 3205401)) ||
  # Windows 10
  smb_check_rollup(os:"10", sp:0, os_build:"10240", rollup_date:"12_2016", bulletin:bulletin, rollup_kb_list:make_list(3205383)) ||
  smb_check_rollup(os:"10", sp:0, os_build:"10586", rollup_date:"12_2016", bulletin:bulletin, rollup_kb_list:make_list(3205386)) ||
  smb_check_rollup(os:"10", sp:0, os_build:"14393", rollup_date:"12_2016", bulletin:bulletin, rollup_kb_list:make_list(3206632))
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
