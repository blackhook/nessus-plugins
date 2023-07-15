#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.

#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154040);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/03");

  script_cve_id(
    "CVE-2021-26441",
    "CVE-2021-26442",
    "CVE-2021-36953",
    "CVE-2021-36970",
    "CVE-2021-38662",
    "CVE-2021-38663",
    "CVE-2021-40443",
    "CVE-2021-40449",
    "CVE-2021-40454",
    "CVE-2021-40455",
    "CVE-2021-40460",
    "CVE-2021-40463",
    "CVE-2021-40465",
    "CVE-2021-40466",
    "CVE-2021-40467",
    "CVE-2021-40469",
    "CVE-2021-40476",
    "CVE-2021-40477",
    "CVE-2021-40478",
    "CVE-2021-40488",
    "CVE-2021-40489",
    "CVE-2021-41331",
    "CVE-2021-41332",
    "CVE-2021-41335",
    "CVE-2021-41340",
    "CVE-2021-41343",
    "CVE-2021-41345"
  );
  script_xref(name:"IAVA", value:"2021-A-0472-S");
  script_xref(name:"IAVA", value:"2021-A-0475-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/01");
  script_xref(name:"MSKB", value:"5006714");
  script_xref(name:"MSKB", value:"5006729");
  script_xref(name:"MSFT", value:"MS21-5006714");
  script_xref(name:"MSFT", value:"MS21-5006729");

  script_name(english:"KB5006729: Windows Server 2012 R2 Security Update (October 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5006729. It is, therefore, affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5006729 or apply Cumulative Update 5006714");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41345");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Win32k NtGdiResetDC Use After Free Local Privilege Elevation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS21-10';
kbs = make_list(
  '5006714',
  '5006729'
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
                   rollup_date:'10_2021',
                   bulletin:bulletin,
                   rollup_kb_list:[5006714, 5006729])
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
