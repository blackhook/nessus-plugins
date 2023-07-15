#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152422);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/07");

  script_cve_id(
    "CVE-2021-26424",
    "CVE-2021-26425",
    "CVE-2021-26426",
    "CVE-2021-26432",
    "CVE-2021-26433",
    "CVE-2021-34480",
    "CVE-2021-34483",
    "CVE-2021-34484",
    "CVE-2021-34530",
    "CVE-2021-34533",
    "CVE-2021-34534",
    "CVE-2021-34535",
    "CVE-2021-34536",
    "CVE-2021-34537",
    "CVE-2021-36926",
    "CVE-2021-36932",
    "CVE-2021-36933",
    "CVE-2021-36936",
    "CVE-2021-36937",
    "CVE-2021-36938",
    "CVE-2021-36947"
  );
  script_xref(name:"MSKB", value:"5005040");
  script_xref(name:"MSFT", value:"MS21-5005040");
  script_xref(name:"IAVA", value:"2021-A-0373-S");
  script_xref(name:"IAVA", value:"2021-A-0374-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/21");

  script_name(english:"KB5005040: Windows 10 version 1507 LTS Security Update (August 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5005040.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-26424,
    CVE-2021-26432, CVE-2021-34530, CVE-2021-34533,
    CVE-2021-34534, CVE-2021-34535, CVE-2021-36936,
    CVE-2021-36937, CVE-2021-36947)

  - An information disclosure vulnerability. An attacker can
    exploit this to disclose potentially sensitive
    information. (CVE-2021-26433, CVE-2021-36926,
    CVE-2021-36932, CVE-2021-36933, CVE-2021-36938)

  - An elevation of privilege vulnerability. An attacker can
    exploit this to gain elevated privileges.
    (CVE-2021-26425, CVE-2021-26426, CVE-2021-34483,
    CVE-2021-34484, CVE-2021-34536, CVE-2021-34537)

  - An memory corruption vulnerability exists. An attacker
    can exploit this to corrupt the memory and cause
    unexpected behaviors within the system/application.
    (CVE-2021-34480)");
  # https://support.microsoft.com/en-us/topic/august-10-2021-kb5005040-os-build-10240-19022-e8bbfa7a-1012-4e18-a2d7-8ae6a8acf8fb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cab780fc");
  script_set_attribute(attribute:"solution", value:
"Apply Cumulative Update KB5005040.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36936");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS21-08';
kbs = make_list(
  '5005040'
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
                   os_build:10240,
                   rollup_date:'08_2021',
                   bulletin:bulletin,
                   rollup_kb_list:[5005040])
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
