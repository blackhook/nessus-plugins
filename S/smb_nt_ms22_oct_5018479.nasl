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
  script_id(166024);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/09");

  script_cve_id(
    "CVE-2022-22035",
    "CVE-2022-24504",
    "CVE-2022-30198",
    "CVE-2022-33634",
    "CVE-2022-33635",
    "CVE-2022-33645",
    "CVE-2022-35770",
    "CVE-2022-37975",
    "CVE-2022-37976",
    "CVE-2022-37977",
    "CVE-2022-37978",
    "CVE-2022-37981",
    "CVE-2022-37982",
    "CVE-2022-37985",
    "CVE-2022-37986",
    "CVE-2022-37987",
    "CVE-2022-37988",
    "CVE-2022-37989",
    "CVE-2022-37990",
    "CVE-2022-37991",
    "CVE-2022-37993",
    "CVE-2022-37994",
    "CVE-2022-37997",
    "CVE-2022-37999",
    "CVE-2022-38000",
    "CVE-2022-38022",
    "CVE-2022-38026",
    "CVE-2022-38029",
    "CVE-2022-38031",
    "CVE-2022-38032",
    "CVE-2022-38033",
    "CVE-2022-38034",
    "CVE-2022-38037",
    "CVE-2022-38038",
    "CVE-2022-38040",
    "CVE-2022-38041",
    "CVE-2022-38042",
    "CVE-2022-38043",
    "CVE-2022-38044",
    "CVE-2022-38047",
    "CVE-2022-38051",
    "CVE-2022-41033",
    "CVE-2022-41081"
  );
  script_xref(name:"MSKB", value:"5018454");
  script_xref(name:"MSKB", value:"5018479");
  script_xref(name:"MSFT", value:"MS22-5018454");
  script_xref(name:"MSFT", value:"MS22-5018479");
  script_xref(name:"IAVA", value:"2022-A-0408-S");
  script_xref(name:"IAVA", value:"2022-A-0409-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/11/01");

  script_name(english:"KB5018479: Windows 7 / Windows Server 2008 R2 Security Update (October 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5018479. It is, therefore, affected by multiple vulnerabilities

  - Microsoft ODBC Driver Remote Code Execution Vulnerability (CVE-2022-38040)

  - Microsoft WDAC OLE DB provider for SQL Server Remote Code Execution Vulnerability (CVE-2022-37982,
    CVE-2022-38031)

  - Active Directory Certificate Services Elevation of Privilege Vulnerability (CVE-2022-37976)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5018454");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5018479");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5018454");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5018479");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5018479 or Cumulative Update 5018454");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38040");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/11");

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

bulletin = 'MS22-10';
kbs = make_list(
  '5018479',
  '5018454'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win7:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'6.1',
                   sp:1,
                   rollup_date:'10_2022',
                   bulletin:bulletin,
                   rollup_kb_list:[5018479, 5018454])
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
