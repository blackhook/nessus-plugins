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
  script_id(153384);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-26435",
    "CVE-2021-36955",
    "CVE-2021-36958",
    "CVE-2021-36959",
    "CVE-2021-36960",
    "CVE-2021-36961",
    "CVE-2021-36962",
    "CVE-2021-36963",
    "CVE-2021-36964",
    "CVE-2021-36965",
    "CVE-2021-36969",
    "CVE-2021-36972",
    "CVE-2021-36974",
    "CVE-2021-38628",
    "CVE-2021-38629",
    "CVE-2021-38633",
    "CVE-2021-38635",
    "CVE-2021-38636",
    "CVE-2021-38638",
    "CVE-2021-38639",
    "CVE-2021-38667",
    "CVE-2021-38671",
    "CVE-2021-40447"
  );
  script_xref(name:"IAVA", value:"2021-A-0429-S");
  script_xref(name:"IAVA", value:"2021-A-0431-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"MSKB", value:"5005607");
  script_xref(name:"MSKB", value:"5005623");
  script_xref(name:"MSFT", value:"MS21-5005607");
  script_xref(name:"MSFT", value:"MS21-5005623");

  script_name(english:"KB5005607: Windows Server 2012 September 2021 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5005607
or cumulative update 5005623. It is, therefore, affected by
multiple vulnerabilities :

  - An elevation of privilege vulnerability. An attacker can
    exploit this to gain elevated privileges.
    (CVE-2021-36955, CVE-2021-36963, CVE-2021-36964,
    CVE-2021-36974, CVE-2021-38628, CVE-2021-38633,
    CVE-2021-38638, CVE-2021-38639, CVE-2021-38667,
    CVE-2021-38671, CVE-2021-40447)

  - An memory corruption vulnerability exists. An attacker
    can exploit this to corrupt the memory and cause
    unexpected behaviors within the system/application.
    (CVE-2021-26435)

  - An information disclosure vulnerability. An attacker can
    exploit this to disclose potentially sensitive
    information. (CVE-2021-36960, CVE-2021-36962,
    CVE-2021-36969, CVE-2021-36972, CVE-2021-38629,
    CVE-2021-38635, CVE-2021-38636)

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-36965, CVE-2021-36958)

  - A denial of service (DoS) vulnerability. An attacker can
    exploit this issue to cause the affected component to
    deny system or application services. (CVE-2021-36961)

  - A session spoofing vulnerability exists. An attacker can
    exploit this to perform actions with the privileges of
    another user. (CVE-2021-36959)");
  # https://support.microsoft.com/en-us/topic/september-14-2021-kb5005607-security-only-update-f2cb16bb-7282-4f2e-a43e-50c4163c877c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e96fa374");
  # https://support.microsoft.com/en-us/topic/september-14-2021-kb5005623-monthly-rollup-bcdb6598-517e-4d53-aa7c-dd7fcfdca204
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?adb97de7");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB5005607 or Cumulative Update KB5005623.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36958");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-36965");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/14");

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

include('audit.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_hotfixes.inc');
include('smb_func.inc');
include('misc_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = "MS21-09";
kbs = make_list('5005607', '5005623');

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Windows 8 EOL
productname = get_kb_item_or_exit('SMB/ProductName', exit_code:1);
if ("Windows 8" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"6.2",
                   sp:0,
                   rollup_date:'09_2021',
                   bulletin:bulletin,
                   rollup_kb_list:[5005607, 5005623])
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
