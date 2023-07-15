#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc. 
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158701);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/26");

  script_cve_id(
    "CVE-2022-21967",
    "CVE-2022-21975",
    "CVE-2022-21977",
    "CVE-2022-21990",
    "CVE-2022-22010",
    "CVE-2022-23253",
    "CVE-2022-23278",
    "CVE-2022-23281",
    "CVE-2022-23283",
    "CVE-2022-23284",
    "CVE-2022-23285",
    "CVE-2022-23286",
    "CVE-2022-23287",
    "CVE-2022-23288",
    "CVE-2022-23290",
    "CVE-2022-23291",
    "CVE-2022-23293",
    "CVE-2022-23294",
    "CVE-2022-23296",
    "CVE-2022-23297",
    "CVE-2022-23298",
    "CVE-2022-23299",
    "CVE-2022-24454",
    "CVE-2022-24459",
    "CVE-2022-24460",
    "CVE-2022-24502",
    "CVE-2022-24503",
    "CVE-2022-24505",
    "CVE-2022-24507",
    "CVE-2022-24508",
    "CVE-2022-24525"
  );
  script_xref(name:"MSFT", value:"MS22-5011487");
  script_xref(name:"MSKB", value:"5011487");
  script_xref(name:"IAVA", value:"2022-A-0111-S");
  script_xref(name:"IAVA", value:"2022-A-0112-S");

  script_name(english:"KB5011487: Windows 10 Version 20H2 / 21H1 / 21H2 Security Update (March 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5011487. It is, therefore, 
affected by multiple vulnerabilities:

  - An elevation of privilege vulnerability. An attacker can
    exploit this to gain elevated privileges.
    (CVE-2022-23283, CVE-2022-23284, CVE-2022-23291,
    CVE-2022-24459, CVE-2022-23296, CVE-2022-24507,
    CVE-2022-24454, CVE-2022-23298, CVE-2022-23290,
    CVE-2022-23288, CVE-2022-24525, CVE-2022-24460,
    CVE-2022-23299, CVE-2022-23293, CVE-2022-23287,
    CVE-2022-21967, CVE-2022-24505, CVE-2022-23286)

  - A denial of service (DoS) vulnerability. An attacker can
    exploit this issue to cause the affected component to
    deny system or application services. (CVE-2022-21975,
    CVE-2022-23253)

  - A security feature bypass vulnerability exists. An
    attacker can exploit this and bypass the security
    feature and perform unauthorized actions compromising
    the integrity of the system/application.
    (CVE-2022-24502)

  - An information disclosure vulnerability. An attacker can
    exploit this to disclose potentially sensitive
    information. (CVE-2022-21977, CVE-2022-22010,
    CVE-2022-23281, CVE-2022-23297, CVE-2022-24503)

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2022-21990,
    CVE-2022-23285, CVE-2022-23294, CVE-2022-24508)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5011487");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5011487.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23284");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-24508");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS22-03';
kbs = make_list(
  '5011487'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'10',
                   sp:0,
                   os_build:19042,
                   rollup_date:'03_2022',
                   bulletin:bulletin,
                   rollup_kb_list:[5011487])
||
  smb_check_rollup(os:'10',
                   sp:0,
                   os_build:19043,
                   rollup_date:'03_2022',
                   bulletin:bulletin,
                   rollup_kb_list:[5011487])
||
  smb_check_rollup(os:'10',
                   sp:0,
                   os_build:19044,
                   rollup_date:'03_2022',
                   bulletin:bulletin,
                   rollup_kb_list:[5011487])
)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
