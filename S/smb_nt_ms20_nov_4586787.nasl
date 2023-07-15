#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(142681);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-1599",
    "CVE-2020-16997",
    "CVE-2020-16998",
    "CVE-2020-16999",
    "CVE-2020-17000",
    "CVE-2020-17001",
    "CVE-2020-17004",
    "CVE-2020-17007",
    "CVE-2020-17011",
    "CVE-2020-17014",
    "CVE-2020-17024",
    "CVE-2020-17025",
    "CVE-2020-17026",
    "CVE-2020-17027",
    "CVE-2020-17028",
    "CVE-2020-17029",
    "CVE-2020-17031",
    "CVE-2020-17032",
    "CVE-2020-17033",
    "CVE-2020-17034",
    "CVE-2020-17036",
    "CVE-2020-17037",
    "CVE-2020-17038",
    "CVE-2020-17040",
    "CVE-2020-17041",
    "CVE-2020-17042",
    "CVE-2020-17043",
    "CVE-2020-17044",
    "CVE-2020-17045",
    "CVE-2020-17046",
    "CVE-2020-17047",
    "CVE-2020-17052",
    "CVE-2020-17054",
    "CVE-2020-17055",
    "CVE-2020-17056",
    "CVE-2020-17058",
    "CVE-2020-17068",
    "CVE-2020-17069",
    "CVE-2020-17071",
    "CVE-2020-17075",
    "CVE-2020-17087",
    "CVE-2020-17088",
    "CVE-2020-17113"
  );
  script_xref(name:"MSKB", value:"4586787");
  script_xref(name:"MSFT", value:"MS20-4586787");
  script_xref(name:"IAVA", value:"2020-A-0512-S");
  script_xref(name:"IAVA", value:"2020-A-0518-S");
  script_xref(name:"IAVA", value:"2020-A-0521-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0135");
  script_xref(name:"CEA-ID", value:"CEA-2020-0124");

  script_name(english:"KB4586787: Windows 10 November 2020 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft 4586787 Product is missing security updates.

  - Remote Desktop Protocol Server Information Disclosure Vulnerability (CVE-2020-16997)

  - DirectX Elevation of Privilege Vulnerability (CVE-2020-16998)

  - Windows WalletService Information Disclosure Vulnerability (CVE-2020-16999)

  - Remote Desktop Protocol Client Information Disclosure Vulnerability (CVE-2020-17000)

  - Windows Print Spooler Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2020-17014.
    (CVE-2020-17001)

  - Windows Graphics Component Information Disclosure Vulnerability (CVE-2020-17004)

  - Windows Remote Access Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2020-17025,
    CVE-2020-17026, CVE-2020-17027, CVE-2020-17028, CVE-2020-17031, CVE-2020-17032, CVE-2020-17033,
    CVE-2020-17034, CVE-2020-17043, CVE-2020-17044. (CVE-2020-17055)

  - Windows Network File System Information Disclosure Vulnerability (CVE-2020-17056)

  - Windows GDI+ Remote Code Execution Vulnerability (CVE-2020-17068)

  - Windows NDIS Information Disclosure Vulnerability (CVE-2020-17069)

  - Windows Delivery Optimization Information Disclosure Vulnerability (CVE-2020-17071)

  - Windows USO Core Worker Elevation of Privilege Vulnerability (CVE-2020-17075)

  - Windows Kernel Local Elevation of Privilege Vulnerability (CVE-2020-17087)

  - Windows Common Log File System Driver Elevation of Privilege Vulnerability (CVE-2020-17088)

  - Windows Camera Codec Information Disclosure Vulnerability (CVE-2020-17113)

  - Windows Spoofing Vulnerability (CVE-2020-1599)

  - Windows Error Reporting Elevation of Privilege Vulnerability (CVE-2020-17007)

  - Windows Port Class Library Elevation of Privilege Vulnerability (CVE-2020-17011)

  - Windows Print Spooler Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2020-17001.
    (CVE-2020-17014)

  - Windows Client Side Rendering Print Provider Elevation of Privilege Vulnerability (CVE-2020-17024)

  - Windows Remote Access Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2020-17026,
    CVE-2020-17027, CVE-2020-17028, CVE-2020-17031, CVE-2020-17032, CVE-2020-17033, CVE-2020-17034,
    CVE-2020-17043, CVE-2020-17044, CVE-2020-17055. (CVE-2020-17025)

  - Windows Remote Access Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2020-17025,
    CVE-2020-17027, CVE-2020-17028, CVE-2020-17031, CVE-2020-17032, CVE-2020-17033, CVE-2020-17034,
    CVE-2020-17043, CVE-2020-17044, CVE-2020-17055. (CVE-2020-17026)

  - Windows Remote Access Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2020-17025,
    CVE-2020-17026, CVE-2020-17028, CVE-2020-17031, CVE-2020-17032, CVE-2020-17033, CVE-2020-17034,
    CVE-2020-17043, CVE-2020-17044, CVE-2020-17055. (CVE-2020-17027)

  - Windows Remote Access Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2020-17025,
    CVE-2020-17026, CVE-2020-17027, CVE-2020-17031, CVE-2020-17032, CVE-2020-17033, CVE-2020-17034,
    CVE-2020-17043, CVE-2020-17044, CVE-2020-17055. (CVE-2020-17028)

  - Windows Canonical Display Driver Information Disclosure Vulnerability (CVE-2020-17029)

  - Windows Remote Access Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2020-17025,
    CVE-2020-17026, CVE-2020-17027, CVE-2020-17028, CVE-2020-17032, CVE-2020-17033, CVE-2020-17034,
    CVE-2020-17043, CVE-2020-17044, CVE-2020-17055. (CVE-2020-17031)

  - Windows Remote Access Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2020-17025,
    CVE-2020-17026, CVE-2020-17027, CVE-2020-17028, CVE-2020-17031, CVE-2020-17033, CVE-2020-17034,
    CVE-2020-17043, CVE-2020-17044, CVE-2020-17055. (CVE-2020-17032)

  - Windows Remote Access Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2020-17025,
    CVE-2020-17026, CVE-2020-17027, CVE-2020-17028, CVE-2020-17031, CVE-2020-17032, CVE-2020-17034,
    CVE-2020-17043, CVE-2020-17044, CVE-2020-17055. (CVE-2020-17033)

  - Windows Remote Access Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2020-17025,
    CVE-2020-17026, CVE-2020-17027, CVE-2020-17028, CVE-2020-17031, CVE-2020-17032, CVE-2020-17033,
    CVE-2020-17043, CVE-2020-17044, CVE-2020-17055. (CVE-2020-17034)

  - Windows Function Discovery SSDP Provider Information Disclosure Vulnerability (CVE-2020-17036)

  - Windows WalletService Elevation of Privilege Vulnerability (CVE-2020-17037)

  - Win32k Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2020-17010. (CVE-2020-17038)

  - Windows Hyper-V Security Feature Bypass Vulnerability (CVE-2020-17040)

  - Windows Print Configuration Elevation of Privilege Vulnerability (CVE-2020-17041)

  - Windows Print Spooler Remote Code Execution Vulnerability (CVE-2020-17042)

  - Windows Remote Access Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2020-17025,
    CVE-2020-17026, CVE-2020-17027, CVE-2020-17028, CVE-2020-17031, CVE-2020-17032, CVE-2020-17033,
    CVE-2020-17034, CVE-2020-17044, CVE-2020-17055. (CVE-2020-17043)

  - Windows Remote Access Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2020-17025,
    CVE-2020-17026, CVE-2020-17027, CVE-2020-17028, CVE-2020-17031, CVE-2020-17032, CVE-2020-17033,
    CVE-2020-17034, CVE-2020-17043, CVE-2020-17055. (CVE-2020-17044)

  - Windows KernelStream Information Disclosure Vulnerability (CVE-2020-17045)

  - Windows Error Reporting Denial of Service Vulnerability (CVE-2020-17046)

  - Windows Network File System Denial of Service Vulnerability (CVE-2020-17047)

  - Scripting Engine Memory Corruption Vulnerability (CVE-2020-17052)

  - Chakra Scripting Engine Memory Corruption Vulnerability This CVE ID is unique from CVE-2020-17048.
    (CVE-2020-17054)

  - Microsoft Browser Memory Corruption Vulnerability (CVE-2020-17058)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.microsoft.com/en-us/help/4586787/windows-10-update-kb4586787
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05343312");
  script_set_attribute(attribute:"solution", value:
"Apply Cumulative Update KB4586787.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17042");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-17040");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = "MS20-11";
kbs = make_list('4586787');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"10240",
                   rollup_date:"11_2020",
                   bulletin:bulletin,
                   rollup_kb_list:[4586787])
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
