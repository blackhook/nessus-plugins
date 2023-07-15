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
  script_id(111695);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/28");

  script_cve_id(
    "CVE-2018-8316",
    "CVE-2018-8351",
    "CVE-2018-8353",
    "CVE-2018-8355",
    "CVE-2018-8371",
    "CVE-2018-8372",
    "CVE-2018-8373",
    "CVE-2018-8385",
    "CVE-2018-8389",
    "CVE-2018-8403"
  );
  script_xref(name:"MSKB", value:"4343205");
  script_xref(name:"MSKB", value:"4343898");
  script_xref(name:"MSKB", value:"4343900");
  script_xref(name:"MSKB", value:"4343901");
  script_xref(name:"MSFT", value:"MS18-4343205");
  script_xref(name:"MSFT", value:"MS18-4343898");
  script_xref(name:"MSFT", value:"MS18-4343900");
  script_xref(name:"MSFT", value:"MS18-4343901");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");

  script_name(english:"Security Updates for Internet Explorer (August 2018)");

  script_set_attribute(attribute:"synopsis", value:
"The Internet Explorer installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Internet Explorer installation on the remote host is
missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2018-8353, CVE-2018-8371, CVE-2018-8373,
    CVE-2018-8389)

  - A remote code execution vulnerability exists in the way
    that Microsoft browsers access objects in memory. The
    vulnerability could corrupt memory in a way that could
    allow an attacker to execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2018-8403)

  - A remote code execution vulnerability exists in the way
    the scripting engine handles objects in memory in
    Microsoft browsers. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2018-8355, CVE-2018-8372, CVE-2018-8385)

  - An information disclosure vulnerability exists when
    affected Microsoft browsers improperly allow cross-frame
    interaction. An attacker who successfully exploited this
    vulnerability could allow an attacker to obtain browser
    frame or window state from a different domain. For an
    attack to be successful, an attacker must persuade a
    user to open a malicious website from a secure website.
    This update addresses the vulnerability by denying
    permission to read the state of the object model, to
    which frames or windows on different domains should not
    have access. (CVE-2018-8351)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly validates hyperlinks before
    loading executable libraries. An attacker who
    successfully exploited this vulnerability could take
    control of an affected system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2018-8316)");
  # https://support.microsoft.com/en-us/help/4343205/cumulative-security-update-for-internet-explorer
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5f0e9e7");
  # https://support.microsoft.com/en-us/help/4343898/windows-81-update-kb4343898
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82e63681");
  # https://support.microsoft.com/en-us/help/4343900/windows-7-update-kb4343900
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7990c33");
  # https://support.microsoft.com/en-us/help/4343901/windows-server-2012-update-kb4343901
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8d177a9");
  # https://support.microsoft.com/en-us/help/4343899/windows-7-update-kb4343899
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a469b20");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4343205
  -KB4343898
  -KB4343900
  -KB4343901

Note that CVE-2018-8316 notes that users can install the
Security-Only patch to cover this vulnerability (KB4343899).
Refer to the link for KB4343899 for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8403");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS18-08';
kbs = make_list(
  '4343898', # Win 8.1 /2012 R2
  '4343900', # Win 7 / 2008 R2
  '4343901', # Server 2012
  '4343205'  # IE Cumulative
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
os = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0',  win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
 audit(AUDIT_OS_SP_NOT_VULN);
if ("Vista" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / Windows Server 2012 R2
  # Internet Explorer 11
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.19101", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4343205") ||

  # Windows Server 2012
  # Internet Explorer 10
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.22522", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"4343205") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.19101", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4343205") ||

  # Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21252", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"4343205")
)
{
  report =  '\nNote: The fix for this issue is available in either of the following updates:\n';
  report += '  - KB4343205 : Cumulative Security Update for Internet Explorer\n';
  if(os == "6.3")
  {
    report += '  - KB4343898 : Windows 8.1 / Server 2012 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS18-08', kb:'4343898', report);
  }
  else if(os == "6.2")
  {
    report += '  - KB4343901 : Windows Server 2012 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS18-08', kb:'4343901', report);
  }
  else if(os == "6.1")
  {
    report += '  - KB4343900 : Windows 7 / Server 2008 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS18-08', kb:'4343900', report);
  }
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
