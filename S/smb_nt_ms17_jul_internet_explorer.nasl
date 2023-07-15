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
  script_id(104891);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-8592",
    "CVE-2017-8594",
    "CVE-2017-8602",
    "CVE-2017-8606",
    "CVE-2017-8607",
    "CVE-2017-8608",
    "CVE-2017-8618"
  );
  script_bugtraq_id(
    99390,
    99396,
    99399,
    99401,
    99408,
    99410,
    99412
  );
  script_xref(name:"MSKB", value:"4025336");
  script_xref(name:"MSKB", value:"4025331");
  script_xref(name:"MSKB", value:"4025341");
  script_xref(name:"MSKB", value:"4025252");
  script_xref(name:"MSFT", value:"MS17-4025336");
  script_xref(name:"MSFT", value:"MS17-4025331");
  script_xref(name:"MSFT", value:"MS17-4025341");
  script_xref(name:"MSFT", value:"MS17-4025252");

  script_name(english:"Security Updates for Internet Explorer (July 2017)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Internet Explorer installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Internet Explorer installation on the remote host is
missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - A security feature bypass vulnerability exists when
    Microsoft browsers improperly handle redirect requests.
    The vulnerability allows Microsoft browsers to bypass
    CORS redirect restrictions, and to follow redirect
    requests that should otherwise be ignored. An attacker
    who successfully exploited the vulnerability could force
    the browser to send data that would otherwise be
    restricted to a destination website of the attacker's
    choice.  (CVE-2017-8592)

  - A spoofing vulnerability exists when an affected
    Microsoft browser does not properly parse HTTP content.
    An attacker who successfully exploited this
    vulnerability could trick a user by redirecting the user
    to a specially crafted website. The specially crafted
    website could either spoof content or serve as a pivot
    to chain an attack with other vulnerabilities in web
    services.  (CVE-2017-8602)

  - A remote code execution vulnerability exists in the way
    that the VBScript engine, when rendered in Internet
    Explorer, handles objects in memory. In a web-based
    attack scenario, an attacker could host a specially
    crafted website that is designed to exploit this
    vulnerability through Internet Explorer and then
    convince a user to view the website. An attacker could
    also embed an ActiveX control marked &quot;safe for
    initialization&quot; in an application or Microsoft
    Office document that hosts the Internet Explorer
    rendering engine. The attacker could also take advantage
    of compromised websites and websites that accept or host
    user-provided content or advertisements. These websites
    could contain specially crafted content that could
    exploit this vulnerability. An attacker who successfully
    exploited this vulnerability could gain the same user
    rights as the current user.  (CVE-2017-8618)

  - A remote code execution vulnerability exists in the way
    JavaScript engines render when handling objects in
    memory in Microsoft browsers. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. An attacker who successfully exploited the
    vulnerability could gain the same user rights as the
    current user.  (CVE-2017-8606, CVE-2017-8607,
    CVE-2017-8608)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory
    via the Microsoft Windows Text Services Framework. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2017-8594)");
  # https://support.microsoft.com/en-us/help/4025336/windows-8-update-kb4025336
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60b27ab9");
  # https://support.microsoft.com/en-us/help/4025331/windows-server-2012-update-kb4025331
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23066c63");
  # https://support.microsoft.com/en-us/help/4025341/windows-7-update-kb4025341
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38156f30");
  # https://support.microsoft.com/en-us/help/4025252/cumulative-security-update-for-internet-explorer-july-11-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9951911");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for the affected versions of Internet Explorer.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
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

bulletin = 'MS17-07';
kbs = make_list(
  '4025336',
  '4025331',
  '4025341',
  '4025252'
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
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.18739", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4025252") ||

  # Windows Server 2012
  # Internet Explorer 10
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.22207", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"4025252") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.18739", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4025252") ||

  # Vista / Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21029", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"4025252") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.16918", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"4025252")
)
{
  report =  '\nNote: The fix for this issue is available in either of the following updates:\n';
  report += '  - KB4025252 : Cumulative Security Update for Internet Explorer\n';
  if(os == "6.3")
  {
    report += '  - KB4025336 : Windows 8.1 / Server 2012 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS17-07', kb:'4025336', report);
  }
  else if(os == "6.2")
  {
    report += '  - KB4025331 : Windows Server 2012 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS17-07', kb:'4025331', report);
  }
  else if(os == "6.1")
  {
    report += '  - KB4025341 : Windows 7 / Server 2008 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS17-07', kb:'4025341', report);
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
