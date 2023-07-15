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
  script_id(100786);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2016-3326",
    "CVE-2017-0167",
    "CVE-2017-0193",
    "CVE-2017-0260",
    "CVE-2017-0282",
    "CVE-2017-0283",
    "CVE-2017-0284",
    "CVE-2017-0285",
    "CVE-2017-0287",
    "CVE-2017-0288",
    "CVE-2017-0289",
    "CVE-2017-0294",
    "CVE-2017-0296",
    "CVE-2017-0299",
    "CVE-2017-0300",
    "CVE-2017-8462",
    "CVE-2017-8464",
    "CVE-2017-8469",
    "CVE-2017-8470",
    "CVE-2017-8471",
    "CVE-2017-8472",
    "CVE-2017-8473",
    "CVE-2017-8475",
    "CVE-2017-8476",
    "CVE-2017-8477",
    "CVE-2017-8478",
    "CVE-2017-8479",
    "CVE-2017-8480",
    "CVE-2017-8481",
    "CVE-2017-8482",
    "CVE-2017-8483",
    "CVE-2017-8484",
    "CVE-2017-8485",
    "CVE-2017-8488",
    "CVE-2017-8489",
    "CVE-2017-8491",
    "CVE-2017-8492",
    "CVE-2017-8517",
    "CVE-2017-8519",
    "CVE-2017-8527",
    "CVE-2017-8528",
    "CVE-2017-8531",
    "CVE-2017-8532",
    "CVE-2017-8533",
    "CVE-2017-8534",
    "CVE-2017-8543",
    "CVE-2017-8544",
    "CVE-2017-8553",
    "CVE-2017-8554"
  );
  script_bugtraq_id(
    97473,
    98810,
    98818,
    98819,
    98820,
    98821,
    98822,
    98824,
    98826,
    98837,
    98839,
    98842,
    98845,
    98847,
    98848,
    98849,
    98851,
    98852,
    98853,
    98854,
    98856,
    98857,
    98858,
    98859,
    98860,
    98862,
    98864,
    98865,
    98869,
    98870,
    98878,
    98884,
    98885,
    98900,
    98901,
    98903,
    98914,
    98918,
    98920,
    98922,
    98923,
    98929,
    98933,
    98940,
    98942,
    98949
  );
  script_xref(name:"MSKB", value:"3217845");
  script_xref(name:"MSKB", value:"4018106");
  script_xref(name:"MSKB", value:"4021903");
  script_xref(name:"MSKB", value:"4021558");
  script_xref(name:"MSKB", value:"4021923");
  script_xref(name:"MSKB", value:"4022008");
  script_xref(name:"MSKB", value:"4022010");
  script_xref(name:"MSKB", value:"4022013");
  script_xref(name:"MSKB", value:"4022883");
  script_xref(name:"MSKB", value:"4022884");
  script_xref(name:"MSKB", value:"4022887");
  script_xref(name:"MSKB", value:"4024402");
  script_xref(name:"MSFT", value:"MS17-3217845");
  script_xref(name:"MSFT", value:"MS17-4018106");
  script_xref(name:"MSFT", value:"MS17-4021903");
  script_xref(name:"MSFT", value:"MS17-4021558");
  script_xref(name:"MSFT", value:"MS17-4021923");
  script_xref(name:"MSFT", value:"MS17-4022008");
  script_xref(name:"MSFT", value:"MS17-4022010");
  script_xref(name:"MSFT", value:"MS17-4022013");
  script_xref(name:"MSFT", value:"MS17-4022883");
  script_xref(name:"MSFT", value:"MS17-4022884");
  script_xref(name:"MSFT", value:"MS17-4022887");
  script_xref(name:"MSFT", value:"MS17-4024402");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/10");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/14");

  script_name(english:"Windows 2008 June 2017 Multiple Security Updates");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing multiple security updates. It is,
therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists when 
    affected Microsoft browsers improperly handle objects 
    in memory. An attacker who successfully exploited the 
    vulnerability could obtain information to further 
    compromise the user's system. (CVE-2016-3326)

  - An information disclosure vulnerability exists when 
    the Windows kernel improperly handles objects in memory. 
    An attacker who successfully exploited this vulnerability 
    could obtain information to further compromise the user's 
    system.(CVE-2017-0167)

  - An elevation of privilege vulnerability exists in
    Windows Hyper-V instruction emulation due to a failure
    to properly enforce privilege levels. An attacker on a
    guest operating system can exploit this to gain elevated
    privileges on the guest. Note that the host operating
    system is not vulnerable. (CVE-2017-0193)

  - A remote code execution vulnerability exists in
    Microsoft Office due to improper validation of
    user-supplied input before loading dynamic link library
    (DLL) files. An unauthenticated, remote attacker can
    exploit this, by convincing a user to open a specially
    crafted file, to execute arbitrary code in the context
    of the current user. (CVE-2017-0260)

  - Multiple information disclosure vulnerabilities exist in
    Windows Uniscribe due to improper handling of objects in
    memory. An unauthenticated, remote attacker can exploit
    these, by convincing a user to visit a specially crafted
    website or to open a specially crafted document file, to
    disclose the contents of memory. (CVE-2017-0282,
    CVE-2017-0284, CVE-2017-0285, CVE-2017-8534)

  - Multiple remote code execution vulnerabilities exist in
    Windows Uniscribe software due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit these, by convincing a user to visit a
    specially crafted website or to open a specially crafted
    document file, to execute arbitrary code in the context
    of the current user. (CVE-2017-0283, CVE-2017-8528)

  - Multiple information disclosure vulnerabilities exist in
    the Windows GDI component due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit these, by convincing a user to visit a
    specially crafted website or to open a specially crafted
    document file, to disclose the contents of memory.
    (CVE-2017-0287, CVE-2017-0288, CVE-2017-0289)

  - A remote code execution vulnerability exists in
    Microsoft Windows due to improper handling of cabinet
    files. An unauthenticated, remote attacker can exploit
    this, by convincing a user to open a specially crafted 
    cabinet file, to execute arbitrary code in the context
    of the current user. (CVE-2017-0294)

  - An elevation of privilege vulnerability exists in
    tdx.sys due to a failure to check the length of a buffer
    prior to copying memory to it. A local attacker can
    exploit this, via a specially crafted application, to
    execute arbitrary code in an elevated context.
    (CVE-2017-0296)

  - Multiple information disclosure vulnerabilities exist in
    the Windows kernel due to improper initialization of
    objects in memory. An authenticated, remote attacker can
    exploit these, via a specially crafted application, to
    disclose the base address of the kernel driver.
    (CVE-2017-0299, CVE-2017-0300, CVE-2017-8462,
    CVE-2017-8485)

  - A remote code execution vulnerability exists in Windows
    due to improper handling of shortcuts. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to insert a removable drive containing
    a malicious shortcut and binary, to automatically
    execute arbitrary code in the context of the current
    user. (CVE-2017-8464)

  - Multiple information disclosure vulnerabilities exist in
    the Windows kernel due to improper initialization of
    objects in memory. An authenticated, remote attacker can
    exploit these, via a specially crafted application, to
    disclose sensitive information. (CVE-2017-8469,
    CVE-2017-8470, CVE-2017-8471, CVE-2017-8472,
    CVE-2017-8473, CVE-2017-8475, CVE-2017-8476,
    CVE-2017-8477, CVE-2017-8478, CVE-2017-8479,
    CVE-2017-8480, CVE-2017-8481, CVE-2017-8482,
    CVE-2017-8483, CVE-2017-8484, CVE-2017-8488,
    CVE-2017-8489, CVE-2017-8491, CVE-2017-8492)

  - A remote code execution vulnerability exists in the way 
    JavaScript engines render when handling objects in memory 
    in Microsoft browsers. The vulnerability could corrupt 
    memory in such a way that an attacker could execute 
    arbitrary code in the context of the current user.
    (CVE-2017-8517)

  - A remote code execution vulnerability exists when Internet 
    Explorer improperly accesses objects in memory. This 
    vulnerability could corrupt memory in such a way that an 
    attacker could execute arbitrary code in the context of 
    the current user. (CVE-2017-8519)

  - A remote code execution vulnerability exists in the
    Windows font library due to improper handling of
    embedded fonts. An unauthenticated, remote attacker can
    exploit this, by convincing a user to visit a specially
    crafted website or open a specially crafted Microsoft
    document, to execute arbitrary code in the context of
    the current user. (CVE-2017-8527)

  - Multiple information disclosure vulnerabilities exist in
    the Windows GDI component due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit these, by convincing a user to visit a
    specially crafted website or open a specially crafted
    document, to disclose the contents of memory.
    (CVE-2017-8531, CVE-2017-8532, CVE-2017-8533)

  - A remote code execution vulnerability exists in the
    Windows Search functionality due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit this, via a specially crafted SMB message,
    to execute arbitrary code. (CVE-2017-8543)

  - An information disclosure vulnerability exists in the
    Windows Search functionality due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit this, via a specially crafted SMB message,
    to disclose sensitive information. (CVE-2017-8544)

  - Multiple information disclosure vulnerabilities exist in
    the Windows kernel due to improper handling of objects
    in memory. An authenticated, remote attacker can exploit
    these, via a specially crafted application, to disclose
    the contents of memory. (CVE-2017-8553, CVE-2017-8554)");
  # https://support.microsoft.com/en-us/help/3217845/hypervisor-code-integrity-elevation-of-privilege-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?092d59db");
  # https://support.microsoft.com/en-us/help/4018106/microsoft-office-remote-code-execution-may-9-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?254e31fd");
  # https://support.microsoft.com/en-us/help/4021558/cumulative-security-update-for-internet-explorer-june-13-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f2d033c7");
  # https://support.microsoft.com/en-us/help/4021903/lnk-remote-code-execution-vulnerability-june-13-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc374e23");
  # https://support.microsoft.com/en-us/help/4021923/windows-tdx-elevation-of-privilege-vulnerability-june-13-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?473a6578");
  # https://support.microsoft.com/en-us/help/4022008/windows-remote-code-execution-vulnerability-june-13-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d418d6a");
  # https://support.microsoft.com/en-us/help/4022010/windows-kernel-information-disclosure-vulnerability-june-13-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?efcac01f");
  # https://support.microsoft.com/en-us/help/4022013/windows-kernel-information-disclosure-vulnerability-june-13-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b34d26a1");
  # https://support.microsoft.com/en-us/help/4022883/windows-kernel-information-disclosure-vulnerability-june-13-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ee2f1c8");
  # https://support.microsoft.com/en-us/help/4022884/security-update-for-windows-server-2008-june-13-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4944e33");
  # https://support.microsoft.com/en-us/help/4022884/security-update-for-windows-server-2008-june-13-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4944e33");
  # https://support.microsoft.com/en-us/help/4024402/windows-search-vulnerabilities-in-windows-server-2008-june-13-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb6eea1d");
  script_set_attribute(attribute:"solution", value:
"Apply the following security updates :

  - KB3217845
  - KB4018106
  - KB4021558
  - KB4021903
  - KB4021923
  - KB4022008
  - KB4022010
  - KB4022013
  - KB4022883
  - KB4022884
  - KB4022887
  - KB4024402");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8543");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'LNK Code Execution Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS17-06';

kbs = make_list(
  "3217845",
  "4018106",
  "4021558",
  "4021903",
  "4021923",
  "4022008",
  "4022010",
  "4022013",
  "4022883",
  "4022884",
  "4022887",
  "4024402"
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

#
# 4024402
files = list_dir(basedir:winsxs, level:0, dir_pat:"windowssearchengine_31bf3856ad364e35_", file_pat:"^mssrch\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('7.0.6002.19805','7.0.6002.24123'),
                            max_versions:make_list('7.0.6002.20000','7.0.6002.99999'),
                            bulletin:bulletin,
                            kb:"4024402", session:the_session);

# 4021923
files = list_dir(basedir:winsxs, level:0, dir_pat:"tdi-over-tcpip_31bf3856ad364e35_", file_pat:"^tdx\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.19787','6.0.6002.24105'),
                            max_versions:make_list('6.0.6002.20000','6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4021923", session:the_session);
# 3217845
if(
  hotfix_is_vulnerable(os:"6.0", arch:"x64", sp:2, file:"hvax64.exe", version:"6.0.6002.19783", min_version:"6.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:"3217845") ||
  hotfix_is_vulnerable(os:"6.0", arch:"x64", sp:2, file:"hvax64.exe", version:"6.0.6002.24101", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"3217845")
  )
  vuln++;

# 4018106
if(
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"rundll32.exe", version:"6.0.6002.19770", min_version:"6.0.6000.16000", dir:"\system32", bulletin:bulletin, kb:"4018106") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"rundll32.exe", version:"6.0.6002.24089", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"4018106")
)
  vuln++;

# 4021903
if(
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"shell32.dll", version:"6.0.6002.19785", min_version:"6.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:"4021903") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"shell32.dll", version:"6.0.6002.24102", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"4021903")
  )
  vuln++;

# 4022008
if(
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32spl.dll", version:"6.0.6002.19783", min_version:"6.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:"4022008") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32spl.dll", version:"6.0.6002.24101", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"4022008")
  )
  vuln++;

# 4022010
if(
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"msmmsp.dll", version:"6.0.6002.19784", min_version:"6.0.6000.16000", dir:"\system32", bulletin:bulletin, kb:"4022010") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"msmmsp.dll", version:"6.0.6002.24102", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"4022010")
  )
  vuln++;

# 4022013
if(
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntoskrnl.exe", version:"6.0.6002.19790", min_version:"6.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:"4022013") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntoskrnl.exe", version:"6.0.6002.24108", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"4022013")
  )
  vuln++;

# 4022883
if(hotfix_is_vulnerable(os:"6.0", sp:2, file:"atmfd.dll", version:"5.1.2.252", dir:"\system32", bulletin:bulletin, kb:"4022883"))
  vuln++;

# 4022884
if(
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"gdi32.dll", version:"6.0.6002.19787", min_version:"6.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:"4022884") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"gdi32.dll", version:"6.0.6002.24105", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"4022884")
  )
  vuln++;

# 4022887
if(
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.19787", min_version:"6.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:"4022887") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.24105", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"4022887")
  )
  vuln++;

# 4021558
if(
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21017", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"4021558") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.16906", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"4021558")
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
