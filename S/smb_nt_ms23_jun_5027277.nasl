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
  script_id(177250);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_cve_id(
    "CVE-2023-29346",
    "CVE-2023-29351",
    "CVE-2023-29358",
    "CVE-2023-29359",
    "CVE-2023-29363",
    "CVE-2023-29368",
    "CVE-2023-29371",
    "CVE-2023-29372",
    "CVE-2023-29373",
    "CVE-2023-32011",
    "CVE-2023-32014",
    "CVE-2023-32015",
    "CVE-2023-32016",
    "CVE-2023-32017",
    "CVE-2023-32020"
  );
  script_xref(name:"MSKB", value:"5027277");
  script_xref(name:"MSKB", value:"5027279");
  script_xref(name:"MSFT", value:"MS23-5027277");
  script_xref(name:"MSFT", value:"MS23-5027279");
  script_xref(name:"IAVA", value:"2023-A-0306");
  script_xref(name:"IAVA", value:"2023-A-0305");

  script_name(english:"KB5027277: Windows Server 2008 Security Update (June 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5027277. It is, therefore, affected by multiple vulnerabilities

  - Windows Pragmatic General Multicast (PGM) Remote Code Execution Vulnerability (CVE-2023-29363,
    CVE-2023-32014, CVE-2023-32015)

  - Microsoft ODBC Driver Remote Code Execution Vulnerability (CVE-2023-29373)

  - Microsoft WDAC OLE DB provider for SQL Server Remote Code Execution Vulnerability (CVE-2023-29372)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5027277");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5027279");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5027277 or Cumulative Update 5027279");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32015");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  '5027279',
  '5027277'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

var share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'6.0',
                   sp:2,
                   rollup_date:'06_2023',
                   bulletin:bulletin,
                   rollup_kb_list:[5027279, 5027277])
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
