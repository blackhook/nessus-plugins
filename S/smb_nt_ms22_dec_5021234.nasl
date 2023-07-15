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
  script_id(168688);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id(
    "CVE-2022-41074",
    "CVE-2022-41076",
    "CVE-2022-41077",
    "CVE-2022-41094",
    "CVE-2022-41121",
    "CVE-2022-44666",
    "CVE-2022-44667",
    "CVE-2022-44668",
    "CVE-2022-44669",
    "CVE-2022-44670",
    "CVE-2022-44671",
    "CVE-2022-44674",
    "CVE-2022-44675",
    "CVE-2022-44676",
    "CVE-2022-44677",
    "CVE-2022-44678",
    "CVE-2022-44679",
    "CVE-2022-44680",
    "CVE-2022-44681",
    "CVE-2022-44682",
    "CVE-2022-44683",
    "CVE-2022-44689",
    "CVE-2022-44697",
    "CVE-2022-44698",
    "CVE-2022-44707"
  );
  script_xref(name:"MSKB", value:"5021234");
  script_xref(name:"MSFT", value:"MS22-5021234");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/01/03");
  script_xref(name:"IAVA", value:"2022-A-0530-S");
  script_xref(name:"IAVA", value:"2022-A-0533-S");

  script_name(english:"KB5021234: Windows 11 Security Update (December 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5021234. It is, therefore, affected by multiple vulnerabilities

  - PowerShell Remote Code Execution Vulnerability (CVE-2022-41076)

  - Windows Subsystem for Linux (WSL2) Kernel Elevation of Privilege Vulnerability (CVE-2022-44689)

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute 
    unauthorized arbitrary commands. (CVE-2022-44676)  

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021234");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5021234");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5021234");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-44676");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-41076");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/13");

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

bulletin = 'MS22-12';
kbs = make_list(
  '5021234'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'10',
                   os_build:22000,
                   rollup_date:'12_2022',
                   bulletin:bulletin,
                   rollup_kb_list:[5021234])
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
