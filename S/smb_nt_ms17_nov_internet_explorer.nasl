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
  script_id(104894);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-11791",
    "CVE-2017-11827",
    "CVE-2017-11834",
    "CVE-2017-11837",
    "CVE-2017-11838",
    "CVE-2017-11843",
    "CVE-2017-11846",
    "CVE-2017-11848",
    "CVE-2017-11855",
    "CVE-2017-11856",
    "CVE-2017-11858",
    "CVE-2017-11869"
  );
  script_bugtraq_id(
    101703,
    101709,
    101715,
    101716,
    101722,
    101725,
    101737,
    101740,
    101741,
    101742,
    101751,
    101753
  );
  script_xref(name:"MSKB", value:"4048957");
  script_xref(name:"MSKB", value:"4048959");
  script_xref(name:"MSKB", value:"4048958");
  script_xref(name:"MSKB", value:"4047206");
  script_xref(name:"MSFT", value:"MS17-4048957");
  script_xref(name:"MSFT", value:"MS17-4048959");
  script_xref(name:"MSFT", value:"MS17-4048958");
  script_xref(name:"MSFT", value:"MS17-4047206");

  script_name(english:"Security Updates for Internet Explorer (November 2017)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Internet Explorer installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Internet Explorer installation on the remote host is
missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - A remote code execution vulnerability exists in the way
    that Microsoft browsers access objects in memory. The
    vulnerability could corrupt memory in a way that could
    allow an attacker to execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2017-11827,
    CVE-2017-11858)

  - A remote code execution vulnerability exists in the way
    the scripting engine handles objects in memory in
    Microsoft browsers. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2017-11837, CVE-2017-11838, CVE-2017-11843,
    CVE-2017-11846)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2017-11855,
    CVE-2017-11856, CVE-2017-11869)

  - An information disclosure vulnerability exists when the
    scripting engine does not properly handle objects in
    memory in Internet Explorer. An attacker who
    successfully exploited the vulnerability could obtain
    information to further compromise the users system.
    (CVE-2017-11834)

  - An information disclosure vulnerability exists when the
    scripting engine does not properly handle objects in
    memory in Microsoft browsers. An attacker who
    successfully exploited the vulnerability could obtain
    information to further compromise the users system.
    (CVE-2017-11791)

  - An information disclosure vulnerability exists when
    Internet Explorer improperly handles page content, which
    could allow an attacker to detect the navigation of the
    user leaving a maliciously crafted page.
    (CVE-2017-11848)");
  # https://support.microsoft.com/en-us/help/4048957/windows-7-update-kb4048957
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ad6eb38");
  # https://support.microsoft.com/en-us/help/4048959/windows-server-2012-update-kb4048959
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6afa4db");
  # https://support.microsoft.com/en-us/help/4048958/windows-81-update-kb4048958
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b7fa1d0");
  # https://support.microsoft.com/en-us/help/4047206/cumulative-security-update-for-internet-explorer
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da0fd90f");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for the affected versions of Internet Explorer.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11827");

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

bulletin = 'MS17-11';
kbs = make_list(
  '4048957',
  '4048959',
  '4048958',
  '4047206'
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
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.18838", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4047206") ||

  # Windows Server 2012
  # Internet Explorer 10
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.22297", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"4047206") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.18838", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4047206") ||

  # Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21073", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"4047206")
)
{
  report =  '\nNote: The fix for this issue is available in either of the following updates:\n';
  report += '  - KB4047206 : Cumulative Security Update for Internet Explorer\n';
  if(os == "6.3")
  {
    report += '  - KB4048958 : Windows 8.1 / Server 2012 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS17-11', kb:'4048958', report);
  }
  else if(os == "6.2")
  {
    report += '  - KB4048959 : Windows Server 2012 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS17-11', kb:'4048959', report);
  }
  else if(os == "6.1")
  {
    report += '  - KB4048957 : Windows 7 / Server 2008 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS17-11', kb:'4048957', report);
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

