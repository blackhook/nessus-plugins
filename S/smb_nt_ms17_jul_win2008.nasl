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
  script_id(101374);
  script_version("1.9");
  script_cvs_date("Date: 2019/04/10 16:10:18");

  script_cve_id(
    "CVE-2017-0170",
    "CVE-2017-8463",
    "CVE-2017-8467",
    "CVE-2017-8486",
    "CVE-2017-8495",
    "CVE-2017-8556",
    "CVE-2017-8557",
    "CVE-2017-8563",
    "CVE-2017-8564",
    "CVE-2017-8565",
    "CVE-2017-8573",
    "CVE-2017-8577",
    "CVE-2017-8578",
    "CVE-2017-8580",
    "CVE-2017-8581",
    "CVE-2017-8582",
    "CVE-2017-8587",
    "CVE-2017-8588",
    "CVE-2017-8589",
    "CVE-2017-8590",
    "CVE-2017-8592",
    "CVE-2017-8606",
    "CVE-2017-8607",
    "CVE-2017-8608",
    "CVE-2017-8618"
  );
  script_bugtraq_id(
    99387,
    99389,
    99394,
    99396,
    99398,
    99400,
    99402,
    99409,
    99413,
    99414,
    99416,
    99419,
    99421,
    99423,
    99424,
    99425,
    99427,
    99428,
    99429,
    99431,
    99439
  );
  script_xref(name:"MSKB", value:"4022746");
  script_xref(name:"MSFT", value:"MS17-4022746");
  script_xref(name:"MSKB", value:"4022748");
  script_xref(name:"MSFT", value:"MS17-4022748");
  script_xref(name:"MSKB", value:"4022914");
  script_xref(name:"MSFT", value:"MS17-4022914");
  script_xref(name:"MSKB", value:"4025240");
  script_xref(name:"MSFT", value:"MS17-4025240");
  script_xref(name:"MSKB", value:"4025252");
  script_xref(name:"MSFT", value:"MS17-4025252");
  script_xref(name:"MSKB", value:"4025397");
  script_xref(name:"MSFT", value:"MS17-4025397");
  script_xref(name:"MSKB", value:"4025398");
  script_xref(name:"MSFT", value:"MS17-4025398");
  script_xref(name:"MSKB", value:"4025409");
  script_xref(name:"MSFT", value:"MS17-4025409");
  script_xref(name:"MSKB", value:"4025497");
  script_xref(name:"MSFT", value:"MS17-4025497");
  script_xref(name:"MSKB", value:"4025674");
  script_xref(name:"MSFT", value:"MS17-4025674");
  script_xref(name:"MSKB", value:"4025872");
  script_xref(name:"MSFT", value:"MS17-4025872");
  script_xref(name:"MSKB", value:"4025877");
  script_xref(name:"MSFT", value:"MS17-4025877");
  script_xref(name:"MSKB", value:"4026059");
  script_xref(name:"MSFT", value:"MS17-4026059");
  script_xref(name:"MSKB", value:"4026061");
  script_xref(name:"MSFT", value:"MS17-4026061");
  script_xref(name:"MSKB", value:"4032955");
  script_xref(name:"MSFT", value:"MS17-4032955");

  script_name(english:"Windows 2008 July 2017 Multiple Security Updates");
  script_summary(english:"Checks the existence of Windows Server 2008 July 2017 Patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing multiple security updates. It is,
therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    Windows Performance Monitor Console due to improper
    parsing of XML input that contains a reference to an
    external entity. An unauthenticated, remote attacker
    can exploit this, by convincing a user to create a
    Data Collector Set and import a specially crafted XML
    file, to disclose arbitrary files via an XML external
    entity (XXE) declaration. (CVE-2017-0170)

  - A remote code execution vulnerability exists in Windows
    Explorer due to improper handling of executable files
    and shares during rename operations. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to open a specially crafted file, to execute arbitrary
    code in the context of the current user. (CVE-2017-8463)

  - Multiple elevation of privilege vulnerabilities exist in
    the Microsoft Graphics component due to improper
    handling of objects in memory. A local attacker can
    exploit these, via a specially crafted application, to
    run arbitrary code in kernel mode. (CVE-2017-8467,
    CVE-2017-8556, CVE-2017-8573, CVE-2017-8577,
    CVE-2017-8578, CVE-2017-8580)

  - An information disclosure vulnerability exists in Win32k
    due to improper handling of objects in memory. A local
    attacker can exploit this, via a specially crafted
    application, to disclose sensitive information.
    (CVE-2017-8486)

  - A security bypass vulnerability exists in Microsoft
    Windows when handling Kerberos ticket exchanges due to a
    failure to prevent tampering with the SNAME field. A
    man-in-the-middle attacker can exploit this to bypass
    the Extended Protection for Authentication security
    feature. (CVE-2017-8495)

  - An information disclosure vulnerability exists in the
    Windows System Information Console due to improper
    parsing of XML input that contains a reference to an
    external entity. An unauthenticated, remote attacker
    can exploit this, by convincing a user to open a
    specially crafted file, to disclose arbitrary files via
    an XML external entity (XXE) declaration.
    (CVE-2017-8557)

  - An elevation of privilege vulnerability exists in
    Windows due to Kerberos falling back to NT LAN Manager
    (NTLM) Authentication Protocol as the default
    authentication protocol. An authenticated, remote
    attacker can exploit this, via an application that
    sends specially crafted traffic to a domain controller,
    to run processes in an elevated context. (CVE-2017-8563)

  - An information disclosure vulnerability exists in the
    Windows kernel due to improper initialization of objects
    in memory. An authenticated, remote attacker can exploit
    this, via a specially crafted application, to bypass
    Kernel Address Space Layout Randomization (KASLR) and
    disclose the base address of the kernel driver.
    (CVE-2017-8564)

  - A remote code execution vulnerability exists in
    PowerShell when handling a PSObject that wraps a CIM
    instance. An authenticated, remote attacker can exploit
    this, via a specially crafted script, to execute
    arbitrary code in a PowerShell remote session.
    (CVE-2017-8565)

  - An elevation of privilege vulnerability exists in
    Windows due to improper handling of objects in memory. A
    local attacker can exploit this, via a specially crafted
    application, to run arbitrary code in kernel mode.
    (CVE-2017-8581)

  - An information disclosure vulnerability exists in the
    HTTP.sys server application component due to improper
    handling of objects in memory. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted request, to disclose sensitive information.
    (CVE-2017-8582)

  - A denial of service vulnerability exists in Windows
    Explorer that is triggered when Explorer attempts to
    open a non-existent file. An unauthenticated, remote
    attacker can exploit this, by convincing a user to visit
    a specially crafted website, to cause a user's system to
    stop responding. (CVE-2017-8587)

  - A remote code execution vulnerability exists in WordPad
    due to improper parsing of specially crafted files. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to open a specially crafted file, to
    execute arbitrary code in the context of the current
    user. (CVE-2017-8588)

  - A remote code execution vulnerability exists in the
    Windows Search component due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit this, by sending specially crafted messages
    to the Windows Search service, to elevate privileges and
    execute arbitrary code. (CVE-2017-8589)

  - An elevation of privilege vulnerability exists in the
    Windows Common Log File System (CLFS) driver due to
    improper handling of objects in memory. A local attacker
    can exploit this, via a specially crafted application,
    to run processes in an elevated context. (CVE-2017-8590)

  - A security bypass vulnerability exists in Microsoft
    browsers due to improper handling of redirect requests.
    An unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a specially crafted website,
    to bypass CORS redirect restrictions. (CVE-2017-8592)

  - A remote code execution vulnerability exists in the way 
    JavaScript engines render when handling objects in memory 
    in Microsoft browsers. The vulnerability could corrupt memory 
    in such a way that an attacker could execute arbitrary code 
    in the context of the current user. An attacker who successfully 
    exploited the vulnerability could gain the same user rights as 
    the current user. (CVE-2017-8606, CVE-2017-8607, CVE-2017-8608,
    CVE-2017-8618)");
  # https://support.microsoft.com/en-us/help/4022746/security-update-for-kerberos-sname-security-feature-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87cdb7f6");
  # https://support.microsoft.com/en-us/help/4022748/windows-kernel-information-disclosure-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0e35b15");
  # https://support.microsoft.com/en-us/help/4022914/windows-kernel-information-disclosure-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1336095c");
  # https://support.microsoft.com/en-us/help/4025240/microsoft-browser-security-feature-bypass-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d0d50a8");
  # https://support.microsoft.com/en-ca/help/4025252/cumulative-security-update-for-internet-explorer-july-11-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59926d5e");
  # https://support.microsoft.com/en-us/help/4025397/windows-performance-monitor-information-disclosure-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9381ee94");
  # https://support.microsoft.com/en-us/help/4025398/security-update-for-msinfo-exe-information-disclosure-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2683f326");
  # https://support.microsoft.com/en-us/help/4025409/security-update-for-the-windows-elevation-of-privilege-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?423780d0");
  # https://support.microsoft.com/en-us/help/4025497/windows-explorer-remote-code-execution-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?626af1da");
  # https://support.microsoft.com/en-us/help/4025674/windows-explorer-denial-of-service-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf02f1f7");
  # https://support.microsoft.com/en-us/help/4025872/windows-powershell-remote-code-execution-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f364ec16");
  # https://support.microsoft.com/en-us/help/4025877/security-update-for-windows-server-2008-july-11-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?548d2827");
  # https://support.microsoft.com/en-us/help/4026059/windows-clfs-elevation-of-privilege-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?628791cd");
  # https://support.microsoft.com/en-us/help/4026061/security-update-for-the-wordpad-remote-code-execution-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff6e3fd2");
  # https://support.microsoft.com/en-us/help/4032955/windows-search-remote-code-execution-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54a9e296");
  script_set_attribute(attribute:"solution", value:
"Apply the following security updates :

  - 4022746
  - 4022748
  - 4022914
  - 4025240
  - 4025252
  - 4025397
  - 4025398
  - 4025409
  - 4025497
  - 4025674
  - 4025872
  - 4025877
  - 4026059
  - 4026061
  - 4032955");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

if (!defined_func("nasl_level") || nasl_level() < 6000 ) exit(0);

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS17-07';

kbs = make_list(
  "4022746",
  "4022748",
  "4022914",
  "4025240",
  "4025252",
  "4025397",
  "4025398",
  "4025409",
  "4025497",
  "4025674",
  "4025872",
  "4025877",
  "4026059",
  "4026061",
  "4032955"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

# KBs only apply to Windows 2008
if (hotfix_check_sp_range(vista:'2') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Vista" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

if (hotfix_check_fversion_init() == HCF_CONNECT) exit(0, "Unable to create SMB session.");

winsxs = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\WinSxS", string:systemroot);
winsxs_share = hotfix_path2share(path:systemroot);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:winsxs_share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, winsxs_share);
}

the_session = make_array(
  'login',    login,
  'password', pass,
  'domain',   domain,
  'share',    winsxs_share
);

vuln = 0;

# 4025872
arch = get_kb_item('SMB/ARCH');

switch (arch)
{
  case "x86":
    files = list_dir(basedir:winsxs, level:0, dir_pat:"x86_microsoft-windows-powershell-exe_31bf3856ad364e35_7.1.6002.16398_none_2442a61e294c7c71", file_pat:"^powershell\.exe$", max_recurse:1);
    break;
  case "x64":
    files = list_dir(basedir:winsxs, level:0, dir_pat:"amd64_microsoft-windows-powershell-exe_31bf3856ad364e35_7.1.6002.16398_none_806141a1e1a9eda7", file_pat:"^powershell\.exe$", max_recurse:1);
    break;
  default:
    files = "";
}
if (!empty_or_null(files))
{
  # Checking before registry key check for session handling.
  files = list_dir(basedir:winsxs, level:0, dir_pat:"msil_system.management.automation_31bf3856ad364e35", file_pat:"^System\.Management\.Automation\.dll$", max_recurse:1);
  vuln += hotfix_check_winsxs(os:'6.0',
                              sp:2,
                              files:files,
                              versions:make_list('6.2.9200.22198'),
                              max_versions:make_list('6.2.9200.99999'),
                              bulletin:bulletin,
                              kb:"4025872", session:the_session);
}

# CVE-2017-8563 applies to Server 2008 and a
# registry key is required if the target is
# a domain controller.
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Is target a DC?
ret = get_registry_value(
  handle:hklm,
  item:"SYSTEM\CurrentControlSet\Control\ProductOptions\ProductType"
);

if (!isnull(ret) && ret == 'LanmanNT')
{
  # Target is a DC.
  # Does target have required key for CVE-2017-8563 fix?
  ret = get_registry_value(
    handle:hklm,
    item:"SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding"
  );
  if (isnull(ret) || (ret != '1' && ret != '2'))
  {
      vuln++;
      reg_key_note =
        '\n  The registry key "SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\\LdapEnforceChannelBinding"' +
        '\n  is missing or is not equal to "1" or "2"' +
        '\n';
      hotfix_add_report(reg_key_note, bulletin:bulletin);
  }
}

RegCloseKey(handle:hklm);
close_registry(close:FALSE);

# 4022746
if(
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"kerberos.dll", version:"6.0.6002.19810", min_version:"6.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:"4022746") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"kerberos.dll", version:"6.0.6002.24130", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"4022746")
  )
  vuln++;

# 4022748
if(
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"netio.sys", version:"6.0.6002.19805", min_version:"6.0.6000.16000", dir:"\system32\drivers", bulletin:bulletin, kb:"4022748") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"netio.sys", version:"6.0.6002.24125", min_version:"6.0.6002.20000", dir:"\system32\drivers", bulletin:bulletin, kb:"4022748")
)
  vuln++;

# 4022914
if(
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"http.sys", version:"6.0.6002.19812", min_version:"6.0.6002.16000", dir:"\system32\drivers", bulletin:bulletin, kb:"4022914") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"http.sys", version:"6.0.6002.24132", min_version:"6.0.6002.20000", dir:"\system32\drivers", bulletin:bulletin, kb:"4022914")
  )
  vuln++;

# 4025240
if(hotfix_is_vulnerable(os:"6.0", sp:2, file:"msxml3.dll", version:"8.100.5015.0", dir:"\system32", bulletin:bulletin, kb:"4025240"))
  vuln++;

# 4025397
if(
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"perfmon.exe", version:"6.0.6002.19810", min_version:"6.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:"4025397") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"perfmon.exe", version:"6.0.6002.24130", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"4025397")
  )
  vuln++;

# 4025398
if(
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"msinfo32.exe", version:"6.0.6002.19810", min_version:"6.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:"4025398") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"msinfo32.exe", version:"6.0.6002.24130", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"4025398")
  )
  vuln++;

# 4025409
if(
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"wldap32.dll", version:"6.0.6002.19810", min_version:"6.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:"4025409") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"wldap32.dll", version:"6.0.6002.24130", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"4025409")
  )
  vuln++;

# 4025497
if(
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"browseui.dll", version:"6.0.6002.19806", min_version:"6.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:"4025497") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"browseui.dll", version:"6.0.6002.24126", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"4025497")
  )
  vuln++;

# 4025674
if(
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntfs.sys", version:"6.0.6002.19816", min_version:"6.0.6002.16000", dir:"\system32\drivers", bulletin:bulletin, kb:"4025674") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntfs.sys", version:"6.0.6002.24136", min_version:"6.0.6002.20000", dir:"\system32\drivers", bulletin:bulletin, kb:"4025674")
  )
  vuln++;

# 4025877
if(
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.19816", min_version:"6.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:"4025877") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.24136", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"4025877")
  )
  vuln++;

# 4026059
if(
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"clfs.sys", version:"6.0.6002.19810", min_version:"6.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:"4026059") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"clfs.sys", version:"6.0.6002.24130", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"4026059")
  )
  vuln++;

# 4032955
if(
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"query.dll", version:"6.0.6002.19829", min_version:"6.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:"4032955") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"query.dll", version:"6.0.6002.24149", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"4032955")
  )
  vuln++;

# 4025252
if(
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21029", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"4025252") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.16918", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"4025252")
)
  vuln++;

# 4026061
program_files = hotfix_get_programfilesdir();
if(
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"wordpad.exe", version:"6.0.6002.19812", min_version:"6.0.6002.16000", dir:"\windows nt\accessories", path:program_files, bulletin:bulletin, kb:"4026061") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"wordpad.exe", version:"6.0.6002.24133", min_version:"6.0.6002.20000", dir:"\windows nt\accessories", path:program_files, bulletin:bulletin, kb:"4026061")
  )
  vuln++;


if (vuln > 0)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
