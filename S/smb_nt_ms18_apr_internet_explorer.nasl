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
  script_id(108971);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id(
    "CVE-2018-0870",
    "CVE-2018-0981",
    "CVE-2018-0987",
    "CVE-2018-0988",
    "CVE-2018-0989",
    "CVE-2018-0991",
    "CVE-2018-0996",
    "CVE-2018-0997",
    "CVE-2018-1000",
    "CVE-2018-1001",
    "CVE-2018-1004",
    "CVE-2018-1018",
    "CVE-2018-1020"
  );
  script_xref(name:"MSKB", value:"4093114");
  script_xref(name:"MSKB", value:"4093123");
  script_xref(name:"MSKB", value:"4093118");
  script_xref(name:"MSKB", value:"4092946");
  script_xref(name:"MSFT", value:"MS18-4093114");
  script_xref(name:"MSFT", value:"MS18-4093123");
  script_xref(name:"MSFT", value:"MS18-4093118");
  script_xref(name:"MSFT", value:"MS18-4092946");

  script_name(english:"Security Updates for Internet Explorer (April 2018)");
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
    current user.  (CVE-2018-1004)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2018-0870,
    CVE-2018-0991, CVE-2018-0997, CVE-2018-1018,
    CVE-2018-1020)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2018-0988, CVE-2018-0996, CVE-2018-1001)

  - An information disclosure vulnerability exists in the
    way that the scripting engine handles objects in memory
    in Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could provide an
    attacker with information to further compromise the
    user's computer or data.  (CVE-2018-0981, CVE-2018-0989,
    CVE-2018-1000)

  - An information disclosure vulnerability exists when the
    scripting engine does not properly handle objects in
    memory in Internet Explorer. An attacker who
    successfully exploited the vulnerability could obtain
    information to further compromise the users system.
    (CVE-2018-0987)");
  # https://support.microsoft.com/en-us/help/4093114/windows-81-update-kb4093114
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b665658e");
  # https://support.microsoft.com/en-us/help/4093123/windows-server-2012-update-kb4093123
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e474951c");
  # https://support.microsoft.com/en-us/help/4093118/windows-7-update-kb4093118
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d3b2bb1");
  # https://support.microsoft.com/en-us/help/4092946/cumulative-security-update-for-internet-explorer
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf0e57cc");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4093114
  -KB4093123
  -KB4093118
  -KB4092946");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1004");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/10");

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

bulletin = 'MS18-04';
kbs = make_list(
  '4093123',
  '4088876',
  '4093118',
  '4092946'
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
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.18978", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4092946") ||

  # Windows Server 2012
  # Internet Explorer 10
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.22411", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"4092946") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.18978", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4092946") ||

  # Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21213", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"4092946")
)
{
  report =  '\nNote: The fix for this issue is available in either of the following updates:\n';
  report += '  - KB4092946 : Cumulative Security Update for Internet Explorer\n';
  if(os == "6.3")
  {
    report += '  - KB4093114 : Windows 8.1 / Server 2012 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS18-04', kb:'4093114', report);
  }
  else if(os == "6.2")
  {
    report += '  - KB4093123 : Windows Server 2012 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS18-04', kb:'4093123', report);
  }
  else if(os == "6.1")
  {
    report += '  - KB4093118 : Windows 7 / Server 2008 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS18-04', kb:'4093118', report);
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
