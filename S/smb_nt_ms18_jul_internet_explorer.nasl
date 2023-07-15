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
  script_id(110991);
  script_version("1.8");
  script_cvs_date("Date: 2019/06/28 11:31:59");

  script_cve_id(
    "CVE-2018-0949",
    "CVE-2018-8242",
    "CVE-2018-8287",
    "CVE-2018-8288",
    "CVE-2018-8291",
    "CVE-2018-8296"
  );
  script_bugtraq_id(
    104620,
    104622,
    104634,
    104636,
    104637,
    104638
  );
  script_xref(name:"MSKB", value:"4339093");
  script_xref(name:"MSKB", value:"4338815");
  script_xref(name:"MSKB", value:"4338830");
  script_xref(name:"MSKB", value:"4338818");
  script_xref(name:"MSFT", value:"MS18-4339093");
  script_xref(name:"MSFT", value:"MS18-4338815");
  script_xref(name:"MSFT", value:"MS18-4338830");
  script_xref(name:"MSFT", value:"MS18-4338818");

  script_name(english:"Security Updates for Internet Explorer (July 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Internet Explorer installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Internet Explorer installation on the remote host is
missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - A remote code execution vulnerability exists in the way
    the scripting engine handles objects in memory in
    Microsoft browsers. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2018-8287, CVE-2018-8288, CVE-2018-8291)

  - A security feature bypass vulnerability exists when
    Microsoft Internet Explorer improperly handles requests
    involving UNC resources. An attacker who successfully
    exploited the vulnerability could force the browser to
    load data that would otherwise be restricted.
    (CVE-2018-0949)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2018-8242, CVE-2018-8296)");
  # https://support.microsoft.com/en-us/help/4339093/cumulative-security-update-for-internet-explorer
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?156c87ff");
  # https://support.microsoft.com/en-us/help/4338815/windows-81-update-kb4338815
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0106ae8");
  # https://support.microsoft.com/en-us/help/4338830/windows-server-2012-update-kb4338830
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c32edc0");
  # https://support.microsoft.com/en-us/help/4338818/windows-7-update-kb4338818
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d021f588");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4339093
  -KB4338815
  -KB4338830
  -KB4338818");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8296");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/10");

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

bulletin = 'MS18-07';
kbs = make_list(
  '4338815', # Win 8.1 /2012 R2
  '4338818', # Win 7 / 2008 R2
  '4338830', # Server 2012
  '4339093'  # IE Cumulative
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
  # fix on x32 is 19061 and on x64 is 19062
  # can use 19061 to flag both
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.19061", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4339093") ||

  # Windows Server 2012
  # Internet Explorer 10
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.22500", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"4339093") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.19081", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4339093") ||

  # Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21250", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"4339093")
)
{
  report =  '\nNote: The fix for this issue is available in either of the following updates:\n';
  report += '  - KB4339093 : Cumulative Security Update for Internet Explorer\n';
  if(os == "6.3")
  {
    report += '  - KB4338815 : Windows 8.1 / Server 2012 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS18-07', kb:'4338815', report);
  }
  else if(os == "6.2")
  {
    report += '  - KB4338830 : Windows Server 2012 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS18-07', kb:'4338830', report);
  }
  else if(os == "6.1")
  {
    report += '  - KB4338818 : Windows 7 / Server 2008 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS18-07', kb:'4338818', report);
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
