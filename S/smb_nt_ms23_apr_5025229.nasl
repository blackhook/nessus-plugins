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
  script_id(174108);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id(
    "CVE-2023-21554",
    "CVE-2023-21727",
    "CVE-2023-21729",
    "CVE-2023-21769",
    "CVE-2023-24883",
    "CVE-2023-24884",
    "CVE-2023-24885",
    "CVE-2023-24886",
    "CVE-2023-24887",
    "CVE-2023-24912",
    "CVE-2023-24924",
    "CVE-2023-24925",
    "CVE-2023-24926",
    "CVE-2023-24927",
    "CVE-2023-24928",
    "CVE-2023-24929",
    "CVE-2023-24931",
    "CVE-2023-28216",
    "CVE-2023-28217",
    "CVE-2023-28218",
    "CVE-2023-28219",
    "CVE-2023-28220",
    "CVE-2023-28221",
    "CVE-2023-28222",
    "CVE-2023-28223",
    "CVE-2023-28224",
    "CVE-2023-28225",
    "CVE-2023-28226",
    "CVE-2023-28227",
    "CVE-2023-28228",
    "CVE-2023-28229",
    "CVE-2023-28231",
    "CVE-2023-28232",
    "CVE-2023-28235",
    "CVE-2023-28236",
    "CVE-2023-28237",
    "CVE-2023-28238",
    "CVE-2023-28240",
    "CVE-2023-28241",
    "CVE-2023-28243",
    "CVE-2023-28244",
    "CVE-2023-28247",
    "CVE-2023-28248",
    "CVE-2023-28249",
    "CVE-2023-28250",
    "CVE-2023-28252",
    "CVE-2023-28253",
    "CVE-2023-28254",
    "CVE-2023-28255",
    "CVE-2023-28256",
    "CVE-2023-28266",
    "CVE-2023-28267",
    "CVE-2023-28268",
    "CVE-2023-28269",
    "CVE-2023-28270",
    "CVE-2023-28271",
    "CVE-2023-28272",
    "CVE-2023-28273",
    "CVE-2023-28274",
    "CVE-2023-28275",
    "CVE-2023-28276",
    "CVE-2023-28278",
    "CVE-2023-28293",
    "CVE-2023-28298",
    "CVE-2023-28302",
    "CVE-2023-28305",
    "CVE-2023-28306",
    "CVE-2023-28307",
    "CVE-2023-28308"
  );
  script_xref(name:"MSKB", value:"5025229");
  script_xref(name:"MSFT", value:"MS23-5025229");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/05/02");
  script_xref(name:"IAVA", value:"2023-A-0188-S");
  script_xref(name:"IAVA", value:"2023-A-0190-S");

  script_name(english:"KB5025229: Windows 10 version 1809 / Windows Server 2019 Security Update (April 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5025229. It is, therefore, affected by multiple vulnerabilities

  - Microsoft WDAC OLE DB provider for SQL Server Remote Code Execution Vulnerability (CVE-2023-28275)

  - Windows Pragmatic General Multicast (PGM) Remote Code Execution Vulnerability (CVE-2023-28250)

  - Microsoft Message Queuing Remote Code Execution Vulnerability (CVE-2023-21554)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5025229");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5025229");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28275");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-28250");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/11");

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

bulletin = 'MS23-04';
kbs = make_list(
  '5025229'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'10',
                   os_build:17763,
                   rollup_date:'04_2023',
                   bulletin:bulletin,
                   rollup_kb_list:[5025229])
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
