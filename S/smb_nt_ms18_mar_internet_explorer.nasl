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
  script_id(108295);
  script_version("1.11");
  script_cvs_date("Date: 2019/04/05 23:25:09");

  script_cve_id(
    "CVE-2018-0889",
    "CVE-2018-0891",
    "CVE-2018-0927",
    "CVE-2018-0929",
    "CVE-2018-0932",
    "CVE-2018-0935",
    "CVE-2018-0942",
    "CVE-2018-8118"
  );
  script_bugtraq_id(
    103295,
    103298,
    103299,
    103307,
    103309,
    103310,
    103312
  );
  script_xref(name:"MSKB", value:"4088876");
  script_xref(name:"MSKB", value:"4088877");
  script_xref(name:"MSKB", value:"4088875");
  script_xref(name:"MSKB", value:"4089187");
  script_xref(name:"MSFT", value:"MS18-4088876");
  script_xref(name:"MSFT", value:"MS18-4088877");
  script_xref(name:"MSFT", value:"MS18-4088875");
  script_xref(name:"MSFT", value:"MS18-4089187");

  script_name(english:"Security Updates for Internet Explorer (March 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

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
    (CVE-2018-0889, CVE-2018-0935)

  - An elevation of privilege vulnerability exists when
    Internet Explorer fails a check, allowing sandbox
    escape. An attacker who successfully exploited the
    vulnerability could use the sandbox escape to elevate
    privileges on an affected system. This vulnerability by
    itself does not allow arbitrary code execution; however,
    it could allow arbitrary code to be run if the attacker
    uses it in combination with another vulnerability (such
    as a remote code execution vulnerability or another
    elevation of privilege vulnerability) that is capable of
    leveraging the elevated privileges when code execution
    is attempted. The update addresses the vulnerability by
    correcting how Internet Explorer handles zone and
    integrity settings. (CVE-2018-0942)

  - An information disclosure vulnerability exists when
    affected Microsoft browsers improperly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2018-0927,
    CVE-2018-0932)

  - An information disclosure vulnerability exists when
    Internet Explorer improperly handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2018-0929)

  - An information disclosure vulnerability exists when the
    scripting engine does not properly handle objects in
    memory in Microsoft browsers. An attacker who
    successfully exploited the vulnerability could obtain
    information to further compromise the users system.
    (CVE-2018-0891)");
  # https://support.microsoft.com/en-us/help/4088876/windows-81-update-kb4088876
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ace7125");
  # https://support.microsoft.com/en-us/help/4088877/windows-server-2012-update-kb4088877
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae0443e3");
  # https://support.microsoft.com/en-us/help/4088875/windows-7-update-kb4088875
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92fb739c");
  # https://support.microsoft.com/en-us/help/4089187/cumulative-security-update-for-internet-explorer
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2174c09b");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4088876
  -KB4088877
  -KB4088875
  -KB4089187");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/13");

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

bulletin = 'MS18-03';
kbs = make_list(
  '4088877',
  '4088876',
  '4088875',
  '4089187'
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


# Check for 4096040 fix version of 18946 (newer than 4089187, but lower version)
if( os == "6.1" )
{
  new_ver = FALSE;
  path = string(hotfix_get_systemroot()) + "\system32\mshtml.dll";
  ver = hotfix_get_fversion(path:path);
  if(ver['error'] == HCF_OK && !isnull(ver['value']))
  {
    ver = join(ver['value'], sep:".");
    if(ver_compare(ver:ver, fix:"11.0.9600.18946", strict:TRUE) == 0)
      new_ver = TRUE;
  }
}

if (
  # Windows 8.1 / Windows Server 2012 R2
  # Internet Explorer 11
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.18953", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4089187") ||

  # Windows Server 2012
  # Internet Explorer 10
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.22387", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"4089187") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
  ( hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.18953", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4089187") && 
    !new_ver ) ||

  # Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21200", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"4089187")
)
{
  report =  '\nNote: The fix for this issue is available in the following update(s):\n';
  report += '  - KB4089187 : Cumulative Security Update for Internet Explorer\n';

  if(os == "6.3")
  {
    
    report += '  - KB4088877 : Windows 8.1 / Server 2012 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS18-03', kb:'4088877', report);
  }
  else if(os == "6.2")
  {
    report += '  - KB4088876 : Windows Server 2012 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS18-03', kb:'4088876', report);
  }
  else if(os == "6.1")
  {
    report += '  - KB4088875 : Windows 7 / Server 2008 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS18-03', kb:'4088875', report);
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
