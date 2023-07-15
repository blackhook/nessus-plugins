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
  script_id(167113);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/03");

  script_cve_id(
    "CVE-2022-23824",
    "CVE-2022-37966",
    "CVE-2022-37967",
    "CVE-2022-37992",
    "CVE-2022-38023",
    "CVE-2022-41039",
    "CVE-2022-41045",
    "CVE-2022-41047",
    "CVE-2022-41048",
    "CVE-2022-41053",
    "CVE-2022-41056",
    "CVE-2022-41057",
    "CVE-2022-41058",
    "CVE-2022-41073",
    "CVE-2022-41086",
    "CVE-2022-41088",
    "CVE-2022-41090",
    "CVE-2022-41095",
    "CVE-2022-41097",
    "CVE-2022-41098",
    "CVE-2022-41109",
    "CVE-2022-41125",
    "CVE-2022-41128"
  );
  script_xref(name:"MSKB", value:"5020003");
  script_xref(name:"MSKB", value:"5020009");
  script_xref(name:"MSFT", value:"MS22-5020003");
  script_xref(name:"MSFT", value:"MS22-5020009");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/12/09");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/11/29");
  script_xref(name:"IAVA", value:"2022-A-0484-S");
  script_xref(name:"IAVA", value:"2022-A-0473-S");

  script_name(english:"KB5020003: Windows Server 2012 Security Update (November 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5020003. It is, therefore, affected by multiple vulnerabilities

  - AMD: CVE-2022-23824 IBPB and Return Address Predictor Interactions (CVE-2022-23824)

  - Windows Kerberos RC4-HMAC Elevation of Privilege Vulnerability (CVE-2022-37966)

  - Windows Kerberos Elevation of Privilege Vulnerability (CVE-2022-37967)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5020003");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5020009");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5020003 or Cumulative Update 5020009");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41128");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/08");

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

bulletin = 'MS22-11';
kbs = make_list(
  '5020009',
  '5020003'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'6.2',
                   sp:0,
                   rollup_date:'11_2022',
                   bulletin:bulletin,
                   rollup_kb_list:[5020009, 5020003])
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
