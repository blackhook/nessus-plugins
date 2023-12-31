#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94639);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id(
    "CVE-2016-7223",
    "CVE-2016-7224",
    "CVE-2016-7225",
    "CVE-2016-7226"
  );
  script_bugtraq_id(
    94003,
    94016,
    94017,
    94018
  );
  script_xref(name:"MSFT", value:"MS16-138");
  script_xref(name:"MSKB", value:"3197873");
  script_xref(name:"MSKB", value:"3197874");
  script_xref(name:"MSKB", value:"3197876");
  script_xref(name:"MSKB", value:"3197877");
  script_xref(name:"MSKB", value:"3198585");
  script_xref(name:"MSKB", value:"3198586");
  script_xref(name:"MSKB", value:"3200970");
  script_xref(name:"IAVA", value:"2016-A-0317");

  script_name(english:"MS16-138: Security Update for Microsoft Virtual Hard Disk Driver (3199647)");
  script_summary(english:"Checks for the November 2016 Rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple elevation of privilege
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple elevation of privilege vulnerabilities
in the Windows Virtual Hard Disk Driver due to improper handling of
user access to certain files. A local attacker can exploit these, via
a specially crafted application, to manipulate files not intended to
be available to the user.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-138");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2012, 8.1, RT 8.1,
2012 R2, 10, and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7226");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/08");

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

bulletin = 'MS16-138';
kbs = make_list(
  '3197873',
  '3197874',
  '3197876',
  '3197877',
  '3198585',
  '3198586',
  '3200970'
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_NOTE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Windows 8 EOL
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

if (
  # 8.1 / 2012 R2
  smb_check_rollup(os:"6.3",
                   sp:0,
                   rollup_date: "11_2016",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(3197873, 3197874)) ||
  # 2012
  smb_check_rollup(os:"6.2",
                   sp:0,
                   rollup_date: "11_2016",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(3197876, 3197877)) ||
  # 10 (1507)
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"10240",
                   rollup_date: "11_2016",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(3198585)) ||
  # 10 (1511)
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"10586",
                   rollup_date: "11_2016",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(3198586)) ||
  # 10 (1607) / 2016
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"14393",
                   rollup_date: "11_2016",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(3200970))
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_note();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
