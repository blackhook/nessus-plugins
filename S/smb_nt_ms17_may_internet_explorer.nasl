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
  script_id(104893);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2017-0064",
    "CVE-2017-0222",
    "CVE-2017-0226",
    "CVE-2017-0231",
    "CVE-2017-0238"
  );
  script_bugtraq_id(
    98121,
    98127,
    98139,
    98173,
    98237
  );
  script_xref(name:"MSKB", value:"4019215");
  script_xref(name:"MSKB", value:"4019216");
  script_xref(name:"MSKB", value:"4019264");
  script_xref(name:"MSKB", value:"4018271");
  script_xref(name:"MSFT", value:"MS17-4019215");
  script_xref(name:"MSFT", value:"MS17-4019216");
  script_xref(name:"MSFT", value:"MS17-4019264");
  script_xref(name:"MSFT", value:"MS17-4018271");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/25");

  script_name(english:"Security Updates for Internet Explorer (May 2017)");

  script_set_attribute(attribute:"synopsis", value:
"The Internet Explorer installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Internet Explorer installation on the remote host is
missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - A remote code execution vulnerability exists in the way
    Microsoft Edge handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2017-0238)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    This vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user.  (CVE-2017-0226)

  - A spoofing vulnerability exists when Microsoft browsers
    render SmartScreen Filter. An attacker who successfully
    exploited this vulnerability could trick a user by
    redirecting the user to a specially crafted website. The
    specially crafted website could then either spoof
    content or serve as a pivot to chain an attack with
    other vulnerabilities in web services.  (CVE-2017-0231)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2017-0222)

  - A security feature bypass vulnerability exists in
    Internet Explorer that allows for bypassing Mixed
    Content warnings. This could allow for the loading of
    unsecure content (HTTP) from secure locations (HTTPS).
    (CVE-2017-0064)");
  # https://support.microsoft.com/en-us/help/4019215/windows-8-update-kb4019215
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09cc032f");
  # https://support.microsoft.com/en-us/help/4019216/windows-server-2012-update-kb4019216
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3c95ae3");
  # https://support.microsoft.com/en-us/help/4019264/windows-7-update-kb4019264
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89dd1a9e");
  # https://support.microsoft.com/en-us/help/4018271/cumulative-security-update-for-internet-explorer-may-9-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5470f743");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for the affected versions of Internet Explorer.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-0238");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2023 Tenable Network Security, Inc.");

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

bulletin = 'MS17-05';
kbs = make_list(
  '4019215',
  '4019216',
  '4019264',
  '4018271'
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
os = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0',  win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

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
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.18666", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4018271") ||

  # Windows Server 2012
  # Internet Explorer 10
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.22137", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"4018271") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 8/9/10/11
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.18666", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4018271") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"10.0.9200.22137", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"4018271") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"9.0.8112.21007", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"4018271")   ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"9.0.8112.16896", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"4018271")   ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"8.0.7601.23764", min_version:"8.0.7601.20000", dir:"\system32", bulletin:bulletin, kb:"4018271")   ||

  # Vista / Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21007", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"4018271") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.16896", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"4018271")
)
{
  report =  '\nNote: The fix for this issue is available in either of the following updates:\n';
  report += '  - KB4018271 : Cumulative Security Update for Internet Explorer\n';
  if(os == "6.3")
  {
    report += '  - KB4019215 : Windows 8.1 / Server 2012 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS17-05', kb:'4019215', report);
  }
  else if(os == "6.2")
  {
    report += '  - KB4019216 : Windows Server 2012 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS17-05', kb:'4019216', report);
  }
  else if(os == "6.1")
  {
    report += '  - KB4019264 : Windows 7 / Server 2008 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS17-05', kb:'4019264', report);
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