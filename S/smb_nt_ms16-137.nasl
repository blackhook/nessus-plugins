#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94638);
  script_version("1.15");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2016-7220", "CVE-2016-7237", "CVE-2016-7238");
  script_bugtraq_id(94036, 94040, 94045);
  script_xref(name:"MSFT", value:"MS16-137");
  script_xref(name:"MSKB", value:"3197867");
  script_xref(name:"MSKB", value:"3197868");
  script_xref(name:"MSKB", value:"3197873");
  script_xref(name:"MSKB", value:"3197874");
  script_xref(name:"MSKB", value:"3197876");
  script_xref(name:"MSKB", value:"3197877");
  script_xref(name:"MSKB", value:"3198510");
  script_xref(name:"MSKB", value:"3198585");
  script_xref(name:"MSKB", value:"3198586");
  script_xref(name:"MSKB", value:"3200970");

  script_name(english:"MS16-137: Security Update for Windows Authentication Methods (3199173)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists in
    Windows Virtual Secure Mode due to improper handling of
    objects in memory. An authenticated, remote attacker can
    exploit this, via a specially crafted application, to
    disclose sensitive information. (CVE-2016-7220)

  - A denial of service vulnerability exists in the Local
    Security Authority Subsystem Service (LSASS) when
    handling specially crafted requests. An authenticated,
    remote attacker can exploit this to cause the host to
    become non-responsive. (CVE-2016-7237)

  - An elevation of privilege vulnerability exists due to
    improper handling of NTLM password change requests. An
    authenticated, remote attacker can exploit this, via a
    specially crafted application, to gain administrative
    privileges. (CVE-2016-7238)");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-137");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, 10, and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7238");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
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
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-137';
kbs = make_list('3197867',
                '3197868',
                '3197873',
                '3197874',
                '3197876',
                '3197877',
                '3198510',
                '3198585',
                '3198586',
                '3200970');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"msv1_0.dll", version:"6.0.6002.24025", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3198510") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"msv1_0.dll", version:"6.0.6002.19701", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3198510") ||
  # Windows 7 / Server 2008 R2
  smb_check_rollup(os:"6.1", sp:1, rollup_date:"11_2016", bulletin:bulletin, rollup_kb_list:make_list(3197867, 3197868)) ||
  # Windows Server 2012
  smb_check_rollup(os:"6.2", sp:0, rollup_date:"11_2016", bulletin:bulletin, rollup_kb_list:make_list(3197876, 3197877)) ||
  # Windows 8.1 / Windows Server 2012 R2
  smb_check_rollup(os:"6.3", sp:0, rollup_date:"11_2016", bulletin:bulletin, rollup_kb_list:make_list(3197873, 3197874)) ||
  # Windows 10
  smb_check_rollup(os:"10", sp:0, os_build:"10240", rollup_date:"11_2016", bulletin:bulletin, rollup_kb_list:make_list(3198585)) ||
  smb_check_rollup(os:"10", sp:0, os_build:"10586", rollup_date:"11_2016", bulletin:bulletin, rollup_kb_list:make_list(3198586)) ||
  smb_check_rollup(os:"10", sp:0, os_build:"14393", rollup_date:"11_2016", bulletin:bulletin, rollup_kb_list:make_list(3200970))
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
