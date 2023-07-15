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
  script_id(162202);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/13");

  script_cve_id(
    "CVE-2022-21123",
    "CVE-2022-21125",
    "CVE-2022-21127",
    "CVE-2022-21166",
    "CVE-2022-30135",
    "CVE-2022-30136",
    "CVE-2022-30140",
    "CVE-2022-30141",
    "CVE-2022-30142",
    "CVE-2022-30143",
    "CVE-2022-30146",
    "CVE-2022-30147",
    "CVE-2022-30149",
    "CVE-2022-30151",
    "CVE-2022-30152",
    "CVE-2022-30153",
    "CVE-2022-30154",
    "CVE-2022-30155",
    "CVE-2022-30160",
    "CVE-2022-30161",
    "CVE-2022-30162",
    "CVE-2022-30163",
    "CVE-2022-30164",
    "CVE-2022-30166",
    "CVE-2022-30190"
  );
  script_xref(name:"MSKB", value:"5014738");
  script_xref(name:"MSKB", value:"5014746");
  script_xref(name:"MSFT", value:"MS22-5014738");
  script_xref(name:"MSFT", value:"MS22-5014746");
  script_xref(name:"IAVA", value:"2022-A-0240-S");
  script_xref(name:"IAVA", value:"2022-A-0241-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/05");
  script_xref(name:"CEA-ID", value:"CEA-2022-0022");

  script_name(english:"KB5014746: Windows Server 2012 R2 Security Update (June 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5014746. It is, therefore, affected by multiple vulnerabilities

  - Windows Network File System Remote Code Execution Vulnerability (CVE-2022-30136)

  - Windows Lightweight Directory Access Protocol (LDAP) Remote Code Execution Vulnerability (CVE-2022-30141,
    CVE-2022-30143, CVE-2022-30146, CVE-2022-30149, CVE-2022-30153, CVE-2022-30161)

  - Windows Hyper-V Remote Code Execution Vulnerability (CVE-2022-30163)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5014738");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5014746");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5014746 or Cumulative Update 5014738");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30136");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Office Word MSDTJS');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/14");

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

bulletin = 'MS22-06';
kbs = make_list(
  '5014746',
  '5014738'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'6.3',
                   sp:0,
                   rollup_date:'06_2022',
                   bulletin:bulletin,
                   rollup_kb_list:[5014746, 5014738])
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
