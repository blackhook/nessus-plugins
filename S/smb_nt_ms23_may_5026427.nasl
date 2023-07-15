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
  script_id(175338);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id(
    "CVE-2023-24900",
    "CVE-2023-24903",
    "CVE-2023-24904",
    "CVE-2023-24932",
    "CVE-2023-24940",
    "CVE-2023-24942",
    "CVE-2023-24943",
    "CVE-2023-24945",
    "CVE-2023-28251",
    "CVE-2023-28283",
    "CVE-2023-29324",
    "CVE-2023-29325",
    "CVE-2023-29336"
  );
  script_xref(name:"MSKB", value:"5026408");
  script_xref(name:"MSKB", value:"5026427");
  script_xref(name:"MSFT", value:"MS23-5026408");
  script_xref(name:"MSFT", value:"MS23-5026427");
  script_xref(name:"IAVA", value:"2023-A-0248-S");
  script_xref(name:"IAVA", value:"2023-A-0249-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/05/30");

  script_name(english:"KB5026427: Windows Server 2008 Security Update (May 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5026427. It is, therefore, affected by multiple vulnerabilities

  - Windows Pragmatic General Multicast (PGM) Remote Code Execution Vulnerability (CVE-2023-24943)

  - Windows Lightweight Directory Access Protocol (LDAP) Remote Code Execution Vulnerability (CVE-2023-28283)

  - Windows NTLM Security Support Provider Information Disclosure Vulnerability (CVE-2023-24900)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5026408");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5026427");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5026427 or Cumulative Update 5026408");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24943");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/09");

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

bulletin = 'MS23-05';
kbs = make_list(
  '5026427',
  '5026408'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'6.0',
                   sp:2,
                   rollup_date:'05_2023',
                   bulletin:bulletin,
                   rollup_kb_list:[5026427, 5026408])
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
