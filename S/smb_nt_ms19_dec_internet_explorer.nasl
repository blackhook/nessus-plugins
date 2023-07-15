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
  script_id(131936);
  script_version("1.5");
  script_cvs_date("Date: 2020/01/17");

  script_cve_id("CVE-2019-1485");
  script_xref(name:"MSKB", value:"4530677");
  script_xref(name:"MSKB", value:"4530691");
  script_xref(name:"MSKB", value:"4530695");
  script_xref(name:"MSKB", value:"4530702");
  script_xref(name:"MSKB", value:"4530734");
  script_xref(name:"MSFT", value:"MS19-4530677");
  script_xref(name:"MSFT", value:"MS19-4530691");
  script_xref(name:"MSFT", value:"MS19-4530695");
  script_xref(name:"MSFT", value:"MS19-4530702");
  script_xref(name:"MSFT", value:"MS19-4530734");

  script_name(english:"Security Updates for Internet Explorer (December 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Internet Explorer installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Internet Explorer installation on the remote host is
missing a security update. It is, therefore, affected by the
following vulnerability :

  - A remote code execution vulnerability exists in the way
    that the VBScript engine handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2019-1485)");
  # https://support.microsoft.com/en-us/help/4530734/windows-7-update-kb4530734
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89866a56");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4530702/windows-8-1-kb4530702");
  # https://support.microsoft.com/en-us/help/4530677/cumulative-security-update-for-internet-explorer
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cac609d");
  # https://support.microsoft.com/en-us/help/4530695/windows-server-2008-update-kb4530695
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b9efd1a");
  # https://support.microsoft.com/en-us/help/4530691/windows-server-2012-update-kb4530691
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c69ab12f");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4530677
  -KB4530691
  -KB4530695
  -KB4530702
  -KB4530734");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1485");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS19-12';
kbs = make_list(
'4530677',
'4530691',
'4530695',
'4530702',
'4530734'
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
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.19540", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4530677") ||

  # Windows Server 2012
  # Internet Explorer 10
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.22931", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"4530677") ||
  # Internet Explorer 11
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"11.0.9600.19572", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4530677") ||
  
  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.19572", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4530677") ||

  # Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21392", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"4530677")
)
{
  report =  '\nNote: The fix for this issue is available in either of the following updates:\n';
  report += '  - KB4530677 : Cumulative Security Update for Internet Explorer\n';
  if(os == "6.3")
  {
    report += '  - KB4530702 : Windows 8.1 / Server 2012 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-12', kb:'4530702', report);
  }
  else if(os == "6.2")
  {
    report += '  - KB4530691 : Windows Server 2012 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-12', kb:'4530691', report);
  }
  else if(os == "6.1")
  {
    report += '  - KB4530734 : Windows 7 / Server 2008 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-12', kb:'4530734', report);
  }
  else if(os == "6.0")
  {
    report += '  - KB4530695 : Windows Server 2008 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-12', kb:'4530695', report);
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
