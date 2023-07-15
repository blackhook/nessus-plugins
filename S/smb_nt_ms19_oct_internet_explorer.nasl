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
  script_id(129728);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/15");

  script_cve_id(
    "CVE-2019-0608",
    "CVE-2019-1238",
    "CVE-2019-1357",
    "CVE-2019-1371"
  );
  script_xref(name:"MSKB", value:"4519976");
  script_xref(name:"MSKB", value:"4520007");
  script_xref(name:"MSKB", value:"4519974");
  script_xref(name:"MSKB", value:"4520005");
  script_xref(name:"MSKB", value:"4520002");
  script_xref(name:"MSFT", value:"MS19-4519976");
  script_xref(name:"MSFT", value:"MS19-4520007");
  script_xref(name:"MSFT", value:"MS19-4519974");
  script_xref(name:"MSFT", value:"MS19-4520005");
  script_xref(name:"MSFT", value:"MS19-4520002");

  script_name(english:"Security Updates for Internet Explorer (October 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Internet Explorer installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Internet Explorer installation on the remote host is
missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - A remote code execution vulnerability exists in the way
    that the VBScript engine handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2019-1238)

  - A spoofing vulnerability exists when Microsoft Browsers
    improperly handle browser cookies. An attacker who
    successfully exploited this vulnerability could trick a
    browser into overwriting a secure cookie with an
    insecure cookie. The insecure cookie could serve as a
    pivot to chain an attack with other vulnerabilities in
    web services.  (CVE-2019-1357)

  - A spoofing vulnerability exists when Microsoft Browsers
    does not properly parse HTTP content. An attacker who
    successfully exploited this vulnerability could
    impersonate a user request by crafting HTTP queries. The
    specially crafted website could either spoof content or
    serve as a pivot to chain an attack with other
    vulnerabilities in web services.  (CVE-2019-0608)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2019-1371)");
  # https://support.microsoft.com/en-us/help/4519976/windows-7-update-kb4519976
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60746595");
  # https://support.microsoft.com/en-us/help/4520007/windows-server-2012-update-kb4520007
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d72b58b");
  # https://support.microsoft.com/en-us/help/4519974/cumulative-security-update-for-internet-explorer
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e535add");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4520005/windows-8-1-kb4520005");
  # https://support.microsoft.com/en-us/help/4520002/windows-server-2008-update-kb4520002
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72b9f640");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4519974
  -KB4519976
  -KB4520002
  -KB4520005
  -KB4520007");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1371");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS19-10';
kbs = make_list(
  '4519974',
  '4519976',
  '4520002',
  '4520005',
  '4520007'
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
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.19504", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4519974") ||

  # Windows Server 2012
  # Internet Explorer 10
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.22887", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"4519974") ||
  # Internet Explorer 11
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"11.0.9600.19501", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4519974") ||
  
  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.19504", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4519974") ||

  # Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21379", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"4519974")
)
{
  report =  '\nNote: The fix for this issue is available in either of the following updates:\n';
  report += '  - KB4519974 : Cumulative Security Update for Internet Explorer\n';
  if(os == "6.3")
  {
    report += '  - KB4520005 : Windows 8.1 / Server 2012 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-10', kb:'4520005', report);
  }
  else if(os == "6.2")
  {
    report += '  - KB4520007 : Windows Server 2012 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-10', kb:'4520007', report);
  }
  else if(os == "6.1")
  {
    report += '  - KB4519976 : Windows 7 / Server 2008 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-10', kb:'4519976', report);
  }
  else if(os == "6.0")
  {
    report += '  - KB4520002 : Windows Server 2008 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-10', kb:'4520002', report);
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
