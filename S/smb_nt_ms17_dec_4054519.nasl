#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#
include("compat.inc");

if (description)
{
  script_id(105185);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-11885",
    "CVE-2017-11886",
    "CVE-2017-11887",
    "CVE-2017-11890",
    "CVE-2017-11894",
    "CVE-2017-11895",
    "CVE-2017-11901",
    "CVE-2017-11903",
    "CVE-2017-11906",
    "CVE-2017-11907",
    "CVE-2017-11912",
    "CVE-2017-11913",
    "CVE-2017-11919",
    "CVE-2017-11927",
    "CVE-2017-11930"
  );
  script_bugtraq_id(
    102045,
    102046,
    102047,
    102053,
    102054,
    102055,
    102058,
    102062,
    102063,
    102078,
    102082,
    102091,
    102092,
    102093,
    102095
  );
  script_xref(name:"MSKB", value:"4054522");
  script_xref(name:"MSKB", value:"4054519");
  script_xref(name:"MSFT", value:"MS17-4054522");
  script_xref(name:"MSFT", value:"MS17-4054519");

  script_name(english:"Windows 8.1 and Windows Server 2012 R2 December 2017 Security Updates");
  script_summary(english:"Checks for rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4054522
or cumulative update 4054519. It is, therefore, affected by
multiple vulnerabilities :

  - An information disclosure vulnerability exists when the
    scripting engine does not properly handle objects in
    memory in Microsoft browsers. An attacker who
    successfully exploited the vulnerability could obtain
    information to further compromise the users system.
    (CVE-2017-11919)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2017-11886,
    CVE-2017-11890, CVE-2017-11901, CVE-2017-11903,
    CVE-2017-11907, CVE-2017-11913)

  - A remote code execution vulnerability exists in RPC if
    the server has Routing and Remote Access enabled. An
    attacker who successfully exploited this vulnerability
    could execute code on the target system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2017-11885)

  - A remote code execution vulnerability exists in the way
    the scripting engine handles objects in memory in
    Microsoft browsers. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2017-11894, CVE-2017-11895, CVE-2017-11912,
    CVE-2017-11930)

  - An information disclosure vulnerability exists when
    Internet Explorer improperly handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2017-11887, CVE-2017-11906)

  - An information disclosure vulnerability exists when the
    Windows its:// protocol handler unnecessarily sends
    traffic to a remote site in order to determine the zone
    of a provided URL. This could potentially result in the
    disclosure of sensitive information to a malicious site.
    (CVE-2017-11927)");
  # https://support.microsoft.com/en-us/help/4054522/windows-81-update-kb4054522
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1020239a");
  # https://support.microsoft.com/en-us/help/4054519/windows-81-update-kb4054519
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18bd5547");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB4054522 or Cumulative update KB4054519.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11885");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS17-12";
kbs = make_list('4054522', '4054519');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Windows 8 EOL
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"6.3",
                   sp:0,
                   rollup_date:"12_2017",
                   bulletin:bulletin,
                   rollup_kb_list:[4054522, 4054519])
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
