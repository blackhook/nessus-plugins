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
  script_id(119594);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id(
    "CVE-2018-8619",
    "CVE-2018-8625",
    "CVE-2018-8631",
    "CVE-2018-8643"
  );
  script_bugtraq_id(
    106117,
    106118,
    106119,
    106122
  );
  script_xref(name:"MSKB", value:"4471325");
  script_xref(name:"MSKB", value:"4471320");
  script_xref(name:"MSKB", value:"4471318");
  script_xref(name:"MSKB", value:"4471330");
  script_xref(name:"MSKB", value:"4470199");
  script_xref(name:"MSFT", value:"MS18-4471325");
  script_xref(name:"MSFT", value:"MS18-4471320");
  script_xref(name:"MSFT", value:"MS18-4471318");
  script_xref(name:"MSFT", value:"MS18-4471330");
  script_xref(name:"MSFT", value:"MS18-4470199");

  script_name(english:"Security Updates for Internet Explorer (December 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Internet Explorer installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Internet Explorer installation on the remote host is
missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2018-8631)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2018-8643)

  - A remote code execution vulnerability exists when the
    Internet Explorer VBScript execution policy does not
    properly restrict VBScript under specific conditions. An
    attacker who exploited the vulnerability could run
    arbitrary code with medium-integrity level privileges
    (the permissions of the current user).  (CVE-2018-8619)

  - A remote code execution vulnerability exists in the way
    that the VBScript engine handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2018-8625)");
  # https://support.microsoft.com/en-us/help/4471325/windows-server-2008-update-kb4471325
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2da08abc");
  # https://support.microsoft.com/en-us/help/4471320/windows-8-1-update-kb4471320
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56bb4eaa");
  # https://support.microsoft.com/en-us/help/4471318/windows-7-update-kb4471318
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b518909");
  # https://support.microsoft.com/en-us/help/4471330/windows-server-2012-kb4471330
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?720406bc");
  # https://support.microsoft.com/en-us/help/4470199/cumulative-security-update-for-internet-explorer
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?801bfd5d");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4471325
  -KB4471320
  -KB4471318
  -KB4471330
  -KB4470199");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8643");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS18-12';
kbs = make_list(
  '4471325',
  '4471320',
  '4471318',
  '4471330',
  '4470199'
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
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.19204", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4470199") ||

  # Windows Server 2012
  # Internet Explorer 10
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.22620", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"4470199") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.19204", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4470199") ||

  # Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21291", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"4470199")
)
{
  report =  '\nNote: The fix for this issue is available in either of the following updates:\n';
  report += '  - KB4470199 : Cumulative Security Update for Internet Explorer\n';
  if(os == "6.3")
  {
    report += '  - KB4471320 : Windows 8.1 / Server 2012 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS18-12', kb:'4471320', report);
  }
  else if(os == "6.2")
  {
    report += '  - KB4471330 : Windows Server 2012 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS18-12', kb:'4471330', report);
  }
  else if(os == "6.1")
  {
    report += '  - KB4471318 : Windows 7 / Server 2008 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS18-12', kb:'4471318', report);
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
