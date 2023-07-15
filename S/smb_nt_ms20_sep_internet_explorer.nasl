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
  script_id(140428);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-0878", "CVE-2020-1012");
  script_xref(name:"MSKB", value:"4577010");
  script_xref(name:"MSKB", value:"4577051");
  script_xref(name:"MSKB", value:"4577064");
  script_xref(name:"MSKB", value:"4577066");
  script_xref(name:"MSFT", value:"MS20-4577010");
  script_xref(name:"MSFT", value:"MS20-4577051");
  script_xref(name:"MSFT", value:"MS20-4577064");
  script_xref(name:"MSFT", value:"MS20-4577066");
  script_xref(name:"IAVA", value:"2020-A-0408-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0118");

  script_name(english:"Security Updates for Internet Explorer (September 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Internet Explorer installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Internet Explorer installation on the remote host is
missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - An elevation of privilege vulnerability exists in the
    way that the Wininit.dll handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could execute code with elevated permissions. There are
    multiple ways an attacker could exploit the
    vulnerability:  (CVE-2020-1012)

  - A remote code execution vulnerability exists in the way
    that Microsoft browsers access objects in memory. The
    vulnerability could corrupt memory in a way that could
    allow an attacker to execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2020-0878)");
  # https://support.microsoft.com/en-us/help/4577010/cumulative-security-update-for-internet-explorer
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?573fa982");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4577051/windows-7-update");
  # https://support.microsoft.com/en-us/help/4577064/windows-server-2008-update
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7633d626");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4577066/windows-8-1-update");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4577010
  -KB4577051
  -KB4577064
  -KB4577066");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1012");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS20-09';
kbs = make_list(
'4577010',
'4577038',
'4577064',
'4577066',
'4577051'
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

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
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.19810", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4577010") ||

  # Windows Server 2012
# Internet Explorer 11
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"11.0.9600.19810", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4577010") ||
  
  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.19810", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4577010") ||

  # Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21488", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"4577010")
)
{
  report =  '\nNote: The fix for this issue is available in either of the following updates:\n';
  report += '  - KB4577010 : Cumulative Security Update for Internet Explorer\n';
  if(os == "6.3")
  {
    report += '  - KB4577066 : Windows 8.1 / Server 2012 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS20-09', kb:'4577066', report);
  }
  else if(os == "6.2")
  {
    report += '  - KB4577038 : Windows Server 2012 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS20-09', kb:'4577038', report);
  }
  else if(os == "6.1")
  {
    report += '  - KB4577051 : Windows 7 / Server 2008 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS20-09', kb:'4577051', report);
  }
  else if(os == "6.0")
  {
    report += '  - KB4577064 : Windows Server 2008 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS20-09', kb:'4577064', report);
  }
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}

