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
  script_id(104896);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/17");

  script_cve_id(
    "CVE-2017-8529",
    "CVE-2017-8733",
    "CVE-2017-8736",
    "CVE-2017-8741",
    "CVE-2017-8747",
    "CVE-2017-8748",
    "CVE-2017-8749",
    "CVE-2017-8750"
  );
  script_bugtraq_id(
    98953,
    100737,
    100743,
    100764,
    100765,
    100766,
    100770,
    100771
  );
  script_xref(name:"MSKB", value:"4036586");
  script_xref(name:"MSKB", value:"4038792");
  script_xref(name:"MSKB", value:"4038799");
  script_xref(name:"MSKB", value:"4038777");
  script_xref(name:"MSFT", value:"MS17-4036586");
  script_xref(name:"MSFT", value:"MS17-4038792");
  script_xref(name:"MSFT", value:"MS17-4038799");
  script_xref(name:"MSFT", value:"MS17-4038777");

  script_name(english:"Security Updates for Internet Explorer (September 2017)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Internet Explorer installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Internet Explorer installation on the remote host is
missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - An information disclosure vulnerability exists when
    affected Microsoft scripting engines do not properly
    handle objects in memory. The vulnerability could allow
    an attacker to detect specific files on the user's
    computer.  (CVE-2017-8529)

  - A remote code execution vulnerability exists when
    Microsoft browsers improperly access objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user.  (CVE-2017-8750)

  - A spoofing vulnerability exists when Internet Explorer
    improperly handles specific HTML content. An attacker
    who successfully exploited this vulnerability could
    trick a user into believing that the user was visiting a
    legitimate website. The specially crafted website could
    either spoof content or serve as a pivot to chain an
    attack with other vulnerabilities in web services.
    (CVE-2017-8733)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user.  (CVE-2017-8747,
    CVE-2017-8749)

  - A remote code execution vulnerability exists in the way
    that Microsoft browser JavaScript engines render content
    when handling objects in memory. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. In a web-based attack scenario, an attacker could
    host a specially crafted website that is designed to
    exploit the vulnerability through Microsoft browsers and
    then convince a user to view the website. An attacker
    could also embed an ActiveX control marked &quot;safe
    for initialization&quot; in an application or Microsoft
    Office document that hosts the related rendering engine.
    The attacker could also take advantage of compromised
    websites, and websites that accept or host user-provided
    content or advertisements. These websites could contain
    specially crafted content that could exploit the
    vulnerability. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2017-8741, CVE-2017-8748)

  - An information disclosure vulnerability exists in
    Microsoft browsers due to improper parent domain
    verification in certain functionality. An attacker who
    successfully exploited the vulnerability could obtain
    specific information that is used in the parent domain.
    (CVE-2017-8736)");
  # https://support.microsoft.com/en-us/help/4036586/cumulative-security-update-for-internet-explorer
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26b484bb");
  # https://support.microsoft.com/en-us/help/4038792/windows-8-1-update-kb4038792
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?085e4d22");
  # https://support.microsoft.com/en-us/help/4038799/windows-server-2012-update-kb4038799
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35364720");
  # https://support.microsoft.com/en-us/help/4038777/windows-7-update-kb4038777
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1dbb18cc");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for the affected versions of Internet Explorer.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8741");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");


  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie"); 
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");
  script_copyright(english:"This script is Copyright (C) 2017-2020 Tenable Network Security, Inc.");
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
include("smb_reg_query.inc");

function is_print_fix_enabled(kb)
{
  var keyx86 = "SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX\iexplore.exe";
  var keyx64 = "SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX\iexplore.exe";
  registry_init();
  var result = check_print_fix(key:keyx86);
  var ret_result = FALSE;
  var report = '';
  if(result != 'set')
  {
    report += '\nThe following registry key is required to enable the fix for CVE-2017-8529 and is ' + result + '\n  ';
    report += 'HKLM\\' + keyx86;
    report += '\n';
    ret_result = TRUE;
  }
  var arch = get_kb_item('SMB/ARCH');
  if(!isnull(arch) && arch == 'x64')
  {
    var x64result = check_print_fix(key:keyx64);
    if(x64result != 'set')
    {
      report += '\nThe following registry key is required to enable the fix for CVE-2017-8529 and is ' + x64result + '\n  ';
      report += 'HKLM\\' + keyx64;
      report += '\n';
      ret_result = TRUE;
    }

  }
  close_registry();
  if(ret_result)
  { 
    hotfix_add_report(bulletin:'MS17-06', kb:kb, report);
  }

  return ret_result;
}

function check_print_fix(key)
{
  var hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  var key_h = get_registry_value(handle:hklm, item:key);
  RegCloseKey(handle:hklm);
  if(isnull(key_h))
    return 'missing.';
  else if(key_h == 0)
    return 'not enabled.';
  else
    return 'set';
}
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS17-09';
kbs = make_list(
  '4036586',
  '4038792',
  '4038799',
  '4038777'
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
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.18792", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4036586") ||

  # Windows Server 2012
  # Internet Explorer 10
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.22248", min_version:"10.0.9200.20000", dir:"\system32", bulletin:bulletin, kb:"4036586") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.18792", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4036586") ||

  # Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21046", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"4036586")
)
  hotfix_vuln = TRUE;
  printfixBool = is_print_fix_enabled(kb:'4036586');

if(hotfix_vuln || printfixBool)
{
  if (hotfix_vuln)
  {
    report =  '\nNote: The fix for this issue is available in either of the following updates:\n';
    report += '  - KB4036586 : Cumulative Security Update for Internet Explorer\n';
    if(os == "6.3")
    {
      report += '  - KB4038792 : Windows 8.1 / Server 2012 R2 Monthly Rollup\n';
      hotfix_add_report(bulletin:'MS17-09', kb:'4038792', report);
    }
    else if(os == "6.2")
    {
      report += '  - KB4038799 : Windows Server 2012 Monthly Rollup\n';
      hotfix_add_report(bulletin:'MS17-09', kb:'4038799', report);
    }
    else if(os == "6.1")
    {
      report += '  - KB4038777 : Windows 7 / Server 2008 R2 Monthly Rollup\n';
      hotfix_add_report(bulletin:'MS17-09', kb:'4038777', report);
    }
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
