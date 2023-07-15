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
  script_id(117423);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id(
    "CVE-2018-8315",
    "CVE-2018-8447",
    "CVE-2018-8452",
    "CVE-2018-8457",
    "CVE-2018-8470"
  );
  script_bugtraq_id(
    105207,
    105251,
    105252,
    105257,
    105267
  );
  script_xref(name:"MSKB", value:"4457135");
  script_xref(name:"MSKB", value:"4457426");
  script_xref(name:"MSKB", value:"4457129");
  script_xref(name:"MSKB", value:"4457144");
  script_xref(name:"MSKB", value:"4458010");
  script_xref(name:"MSFT", value:"MS18-4457135");
  script_xref(name:"MSFT", value:"MS18-4457426");
  script_xref(name:"MSFT", value:"MS18-4457129");
  script_xref(name:"MSFT", value:"MS18-4457144");
  script_xref(name:"MSFT", value:"MS18-4458010");

  script_name(english:"Security Updates for Internet Explorer (September 2018)");
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
    (CVE-2018-8457)

  - An information disclosure vulnerability exists when the
    browser scripting engine improperly handle object types.
    An attacker who has successfully exploited this
    vulnerability might be able to read privileged data
    across trust boundaries. In browsing scenarios, an
    attacker could convince a user to visit a malicious site
    and leverage the vulnerability to obtain privileged
    information from the browser process, such as sensitive
    data from other opened tabs. An attacker could also
    inject malicious code into advertising networks used by
    trusted sites or embed malicious code on a compromised,
    but trusted, site. The security update addresses the
    vulnerability by correcting how the browser scripting
    engine handles object types. (CVE-2018-8315)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2018-8447)

  - A security feature bypass vulnerability exists in
    Internet Explorer due to how scripts are handled that
    allows a universal cross-site scripting (UXSS)
    condition. An attacker could use the UXSS vulnerability
    to access any session belonging to web pages currently
    opened (or cached) by the browser at the time the attack
    is triggered.  (CVE-2018-8470)

  - An information disclosure vulnerability exists when the
    scripting engine does not properly handle objects in
    memory in Microsoft browsers. An attacker who
    successfully exploited the vulnerability could obtain
    information to further compromise the users system.
    (CVE-2018-8452)");
  # https://support.microsoft.com/en-us/help/4457135/windows-server-2012-update-kb4457135
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?02ec6b51");
  # https://support.microsoft.com/en-us/help/4457426/cumulative-security-update-for-internet-explorer
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38b6caf5");
  # https://support.microsoft.com/en-us/help/4457129/windows-81-update-kb4457129
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7080d669");
  # https://support.microsoft.com/en-us/help/4457144/windows-7-update-kb4457144
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?955c2a0f");
  # https://support.microsoft.com/en-us/help/4458010/windows-server-2008-update-kb4458010
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a9824bb");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4457135
  -KB4457426
  -KB4457129
  -KB4457144
  -KB4458010");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8457");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
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

bulletin = 'MS18-09';
kb = '4457426';  # IE Cumulative
kbs = make_list(
  '4458010', # Server 2008
  '4457144', # Win 7 / 2008 R2
  '4457135', # Server 2012
  '4457129', # Win 8.1 /2012 R2
  kb  # IE Cumulative
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
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.19130", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Server 2012
  # Internet Explorer 10
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.22550", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.19130", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21261", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  report =  '\nNote: The fix for this issue is available in either of the following updates:\n';
  report += '  - KB4457426 : Cumulative Security Update for Internet Explorer\n';
  if(os == "6.3")
  {
    report += '  - KB4457129 : Windows 8.1 / Server 2012 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS18-09', kb:'', report);
  }
  else if(os == "6.2")
  {
    report += '  - KB4457135 : Windows Server 2012 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS18-09', kb:'', report);
  }
  else if(os == "6.1")
  {
    report += '  - KB4457144 : Windows 7 / Server 2008 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS18-09', kb:'', report);
  }
  else if(os == "6.0")
  {
    report += '  - KB4458010 : Server 2008 SP2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS18-09', kb:'', report);
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
