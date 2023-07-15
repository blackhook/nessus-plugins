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
  script_id(169784);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id(
    "CVE-2023-21524",
    "CVE-2023-21525",
    "CVE-2023-21527",
    "CVE-2023-21532",
    "CVE-2023-21535",
    "CVE-2023-21536",
    "CVE-2023-21537",
    "CVE-2023-21539",
    "CVE-2023-21540",
    "CVE-2023-21541",
    "CVE-2023-21543",
    "CVE-2023-21546",
    "CVE-2023-21547",
    "CVE-2023-21548",
    "CVE-2023-21549",
    "CVE-2023-21550",
    "CVE-2023-21551",
    "CVE-2023-21552",
    "CVE-2023-21555",
    "CVE-2023-21556",
    "CVE-2023-21557",
    "CVE-2023-21558",
    "CVE-2023-21559",
    "CVE-2023-21560",
    "CVE-2023-21561",
    "CVE-2023-21563",
    "CVE-2023-21674",
    "CVE-2023-21675",
    "CVE-2023-21676",
    "CVE-2023-21677",
    "CVE-2023-21678",
    "CVE-2023-21679",
    "CVE-2023-21680",
    "CVE-2023-21681",
    "CVE-2023-21682",
    "CVE-2023-21683",
    "CVE-2023-21724",
    "CVE-2023-21726",
    "CVE-2023-21728",
    "CVE-2023-21730",
    "CVE-2023-21732",
    "CVE-2023-21733",
    "CVE-2023-21739",
    "CVE-2023-21746",
    "CVE-2023-21747",
    "CVE-2023-21748",
    "CVE-2023-21749",
    "CVE-2023-21750",
    "CVE-2023-21752",
    "CVE-2023-21754",
    "CVE-2023-21755",
    "CVE-2023-21757",
    "CVE-2023-21758",
    "CVE-2023-21759",
    "CVE-2023-21760",
    "CVE-2023-21765",
    "CVE-2023-21766",
    "CVE-2023-21767",
    "CVE-2023-21768",
    "CVE-2023-21771",
    "CVE-2023-21772",
    "CVE-2023-21773",
    "CVE-2023-21774",
    "CVE-2023-21776"
  );
  script_xref(name:"MSKB", value:"5022287");
  script_xref(name:"MSFT", value:"MS23-5022287");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/01/31");
  script_xref(name:"IAVA", value:"2023-A-0025-S");
  script_xref(name:"IAVA", value:"2023-A-0027-S");

  script_name(english:"KB5022287: Windows 11 Security Update (January 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5022287. It is, therefore, affected by multiple vulnerabilities

  - Microsoft ODBC Driver Remote Code Execution Vulnerability (CVE-2023-21732)

  - Microsoft WDAC OLE DB provider for SQL Server Remote Code Execution Vulnerability (CVE-2023-21681)

  - Windows Lightweight Directory Access Protocol (LDAP) Remote Code Execution Vulnerability (CVE-2023-21676)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5022287");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5022287");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21732");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-21557");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ancillary Function Driver (AFD) for WinSock Elevation of Privilege');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/10");

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

bulletin = 'MS23-01';
kbs = make_list(
  '5022287'
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
                   rollup_date:'01_2023',
                   bulletin:bulletin,
                   rollup_kb_list:[5022287])
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
