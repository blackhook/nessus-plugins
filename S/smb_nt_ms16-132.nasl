#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(94633);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2016-7205",
    "CVE-2016-7210",
    "CVE-2016-7217",
    "CVE-2016-7256"
  );
  script_bugtraq_id(
    94030,
    94033,
    94066,
    94156
  );
  script_xref(name:"MSFT", value:"MS16-132");
  script_xref(name:"MSKB", value:"3203859");
  script_xref(name:"MSKB", value:"3197867");
  script_xref(name:"MSKB", value:"3197868");
  script_xref(name:"MSKB", value:"3197873");
  script_xref(name:"MSKB", value:"3197874");
  script_xref(name:"MSKB", value:"3197876");
  script_xref(name:"MSKB", value:"3197877");
  script_xref(name:"MSKB", value:"3198585");
  script_xref(name:"MSKB", value:"3198586");
  script_xref(name:"MSKB", value:"3200970");
  script_xref(name:"IAVA", value:"2016-A-0318");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"MS16-132: Security Update for Microsoft Graphics Component (3199120)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in the
    Windows Animation Manager due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit this vulnerability by convincing a user to
    visit a specially crafted website, resulting in the
    execution of arbitrary code in the context of the
    current user. (CVE-2016-7205)

  - An information disclosure vulnerability exists in the
    ATMFD component due to improper handling of Open Type
    fonts. An unauthenticated, remote attacker can exploit
    this vulnerability by convincing a user to visit a
    specially crafted website or open a specially crafted
    file, resulting in the disclosure of sensitive
    information. (CVE-2016-7210)

  - A remote code execution vulnerability exists in the
    Windows Media Foundation due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit this vulnerability by convincing a user to
    visit a specially crafted website or open a specially
    crafted document, resulting in the execution of
    arbitrary code in the context of the current user.
    (CVE-2016-7217)

  - A remote code execution vulnerability exists in the
    Windows font library due to improper handling of
    embedded Open Type fonts. An unauthenticated, remote
    attacker can exploit this vulnerability by convincing a
    user to visit a specially crafted website or open a
    specially crafted document, resulting in the execution
    of arbitrary code in the context of the current user.
    (CVE-2016-7256)");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-132");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, 10, and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7256");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2022 Tenable Network Security, Inc.");

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
include("install_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-132';
kbs = make_list(
  "3203859", # Windows Vista / 2008
  "3197867", # Windows 7 / 2008 R2 Security Only
  "3197868", # Windows 7 / 2008 R2 Monthly Rollup
  "3197873", # Windows 8.1 / 2012 R2 Security Only
  "3197874", # Windows 8.1 / 2012 R2 / RT 8.1 Monthly Rollup
  "3197876", # Windows 2012 Security Only
  "3197877", # Windows 2012 Monthly Rollup
  "3198585", # Windows 10 RTM
  "3198586", # Windows 10 1511
  "3200970"  # Windows 10 1607
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  #  "3200970", # Windows 10 1607
  smb_check_rollup(os:"10", sp:0, os_build:"14393", rollup_date:"11_2016", bulletin:bulletin, rollup_kb_list:make_list(3200970)) ||

  #  "3198586", # Windows 10 1511
  smb_check_rollup(os:"10", sp:0, os_build:"10586", rollup_date:"11_2016", bulletin:bulletin, rollup_kb_list:make_list(3198586)) ||

  #  "3198585", # Windows 10 RTM
  smb_check_rollup(os:"10", sp:0, os_build:"10240", rollup_date:"11_2016", bulletin:bulletin, rollup_kb_list:make_list(3198585)) ||

  #  "3197873", # Windows 8.1 / 2012 R2 Security Only
  #  "3197874", # Windows 8.1 / 2012 R2 / RT 8.1 Monthly Rollup
  smb_check_rollup(os:"6.3", sp:0, rollup_date:"11_2016", bulletin:bulletin, rollup_kb_list:make_list(3197873, 3197874)) ||

  #  "3197876", # Windows 2012 Security Only
  #  "3197877", # Windows 2012 Monthly Rollup
  smb_check_rollup(os:"6.2", sp:0, rollup_date:"11_2016", bulletin:bulletin, rollup_kb_list:make_list(3197876, 3197877)) ||

  #  "3197867", # Windows 7 / 2008 R2 Security Only
  #  "3197868", # Windows 7 / 2008 R2 Monthly Rollup
  smb_check_rollup(os:"6.1", sp:1, rollup_date:"11_2016", bulletin:bulletin, rollup_kb_list:make_list(3197867, 3197868)) ||

  #  "3203859", # Windows Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"atmfd.dll", version:"5.1.2.250", dir:"\system32", bulletin:bulletin, kb:'3203859')
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
