#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.

#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('compat.inc');

if (description)
{
  script_id(177246);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id(
    "CVE-2023-29346",
    "CVE-2023-29351",
    "CVE-2023-29355",
    "CVE-2023-29358",
    "CVE-2023-29359",
    "CVE-2023-29360",
    "CVE-2023-29362",
    "CVE-2023-29363",
    "CVE-2023-29364",
    "CVE-2023-29365",
    "CVE-2023-29367",
    "CVE-2023-29368",
    "CVE-2023-29369",
    "CVE-2023-29370",
    "CVE-2023-29371",
    "CVE-2023-29372",
    "CVE-2023-29373",
    "CVE-2023-32008",
    "CVE-2023-32009",
    "CVE-2023-32011",
    "CVE-2023-32014",
    "CVE-2023-32015",
    "CVE-2023-32016",
    "CVE-2023-32017",
    "CVE-2023-32019",
    "CVE-2023-32020",
    "CVE-2023-32021",
    "CVE-2023-32022"
  );
  script_xref(name:"MSKB", value:"5027219");
  script_xref(name:"MSFT", value:"MS23-5027219");
  script_xref(name:"IAVA", value:"2023-A-0306");
  script_xref(name:"IAVA", value:"2023-A-0305");

  script_name(english:"KB5027219: Windows 10 Version 1607 and Windows Server 2016 Security Update (June 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5027219. It is, therefore, affected by multiple vulnerabilities

  - Windows Pragmatic General Multicast (PGM) Remote Code Execution Vulnerability (CVE-2023-29363,
    CVE-2023-32014, CVE-2023-32015)

  - Windows Collaborative Translation Framework Elevation of Privilege Vulnerability (CVE-2023-32009)

  - Microsoft ODBC Driver Remote Code Execution Vulnerability (CVE-2023-29373)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5027219");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5027219");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32015");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var bulletin = 'MS23-06';
var kbs = make_list(
  '5027219'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

var share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'10',
                   os_build:14393,
                   rollup_date:'06_2023',
                   bulletin:bulletin,
                   rollup_kb_list:[5027219])
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
