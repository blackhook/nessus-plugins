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
  script_id(102273);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/04");

  script_cve_id(
    "CVE-2017-0174",
    "CVE-2017-0250",
    "CVE-2017-0299",
    "CVE-2017-8593",
    "CVE-2017-8620",
    "CVE-2017-8624",
    "CVE-2017-8633",
    "CVE-2017-8636",
    "CVE-2017-8641",
    "CVE-2017-8651",
    "CVE-2017-8653",
    "CVE-2017-8666",
    "CVE-2017-8668",
    "CVE-2017-8691"
  );
  script_bugtraq_id(
    98100,
    100032,
    100034,
    100038,
    100061,
    100089
  );
  script_xref(name:"MSKB", value:"4022750");
  script_xref(name:"MSFT", value:"MS17-4022750");
  script_xref(name:"MSKB", value:"4034733");
  script_xref(name:"MSFT", value:"MS17-4034733");
  script_xref(name:"MSKB", value:"4034034");
  script_xref(name:"MSFT", value:"MS17-4034034");
  script_xref(name:"MSKB", value:"4034741");
  script_xref(name:"MSFT", value:"MS17-4034741");
  script_xref(name:"MSKB", value:"4034744");
  script_xref(name:"MSFT", value:"MS17-4034744");
  script_xref(name:"MSKB", value:"4034745");
  script_xref(name:"MSFT", value:"MS17-4034745");
  script_xref(name:"MSKB", value:"4034775");
  script_xref(name:"MSFT", value:"MS17-4034775");
  script_xref(name:"MSKB", value:"4035055");
  script_xref(name:"MSFT", value:"MS17-4035055");
  script_xref(name:"MSKB", value:"4035056");
  script_xref(name:"MSFT", value:"MS17-4035056");
  script_xref(name:"MSKB", value:"4035679");
  script_xref(name:"MSFT", value:"MS17-4035679");

  script_name(english:"Windows 2008 August 2017 Multiple Security Updates");
  script_summary(english:"Checks the existence of Windows Server 2008 August 2017 Patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing multiple security updates released
on 2017/08/08. It is, therefore, affected by multiple
vulnerabilities :

- A denial of service vulnerability exists when Microsoft Windows
    improperly handles NetBIOS packets. An attacker who successfully
    exploited this vulnerability could cause a target computer to
    become completely unresponsive. A remote unauthenticated attacker
    could exploit this vulnerability by sending a series of TCP
    packets to a target system, resulting in a permanent denial of
    service condition. The update addresses the vulnerability by
    correcting how the Windows network stack handles NetBIOS traffic.
    (CVE-2017-0174)

  - A buffer overflow vulnerability exists in the Microsoft JET
    Database Engine that could allow remote code execution on an
    affected system. An attacker who successfully exploited this
    vulnerability could take complete control of an affected system.
    An attacker could then install programs; view, change, or delete
    data; or create new accounts with full user rights. Users whose
    accounts are configured to have fewer user rights on the system
    could be less impacted than users who operate with administrative
    user rights. Exploitation of this vulnerability requires that a
    user open or preview a specially crafted database file while using
    an affected version of Microsoft Windows. In an email attack
    scenario, an attacker could exploit the vulnerability by sending a
    specially crafted database file to the user and then convincing
    the user to open the file. The update addresses the vulnerability
    by modifying how the Microsoft JET Database Engine handles objects
    in memory. (CVE-2017-0250)

  - An information disclosure vulnerability exists when the Windows 
    kernel fails to properly initialize a memory address, allowing an 
    attacker to retrieve information that could lead to a Kernel Address 
    Space Layout Randomization (KASLR) bypass. (CVE-2017-0299)

  - An elevation of privilege vulnerability exists in Windows when the
    Win32k component fails to properly handle objects in memory. An
    attacker who successfully exploited this vulnerability could run
    arbitrary code in kernel mode. An attacker could then install
    programs; view, change, or delete data; or create new accounts
    with full user rights. To exploit this vulnerability, an attacker
    would first have to log on to the system. An attacker could then
    run a specially crafted application that could exploit the
    vulnerability and take control of an affected system. The update
    addresses this vulnerability by correcting how Win32k handles
    objects in memory. (CVE-2017-8593)

  - A remote code execution vulnerability exists when Windows Search
    handles objects in memory. An attacker who successfully exploited
    this vulnerability could take control of the affected system. An
    attacker could then install programs; view, change, or delete
    data; or create new accounts with full user rights. To exploit the
    vulnerability, the attacker could send specially crafted messages
    to the Windows Search service. An attacker with access to a target
    computer could exploit this vulnerability to elevate privileges
    and take control of the computer. Additionally, in an enterprise
    scenario, a remote unauthenticated attacker could remotely trigger
    the vulnerability through an SMB connection and then take control
    of a target computer. The security update addresses the
    vulnerability by correcting how Windows Search handles objects in
    memory. (CVE-2017-8620)

  - An elevation of privilege vulnerability exists when the Windows
    Common Log File System (CLFS) driver improperly handles objects in
    memory. In a local attack scenario, an attacker could exploit this
    vulnerability by running a specially crafted application to take
    control of the affected system. An attacker who successfully
    exploited this vulnerability could run processes in an elevated
    context. The update addresses the vulnerability by correcting how
    CLFS handles objects in memory. Note: The Common Log File System
    (CLFS) is a high-performance, general-purpose log file subsystem
    that dedicated client applications can use and multiple clients
    can share to optimize log access. (CVE-2017-8624)

  - This security update resolves a vulnerability in Windows Error
    Reporting (WER). The vulnerability could allow elevation of
    privilege if successfully exploited by an attacker. An attacker
    who successfully exploited this vulnerability could gain greater
    access to sensitive information and system functionality. This
    update corrects the way the WER handles and executes files.
    (CVE-2017-8633)

  - A remote code execution vulnerability exists in the way that 
    Microsoft browser JavaScript engines render content when 
    handling objects in memory. The vulnerability could corrupt 
    memory in such a way that an attacker could execute arbitrary
    code in the context of the current user. (CVE-2017-8636)

  - A remote code execution vulnerability exists in the way 
    JavaScript engines render when handling objects in memory 
    in Microsoft browsers. The vulnerability could corrupt memory 
    in such a way that an attacker could execute arbitrary code in 
    the context of the current user. An attacker who successfully 
    exploited the vulnerability could gain the same user rights as 
    the current user. If the current user is logged on with 
    administrative user rights, an attacker who successfully exploited 
    the vulnerability could take control of an affected system. An 
    attacker could then install programs; view, change, or delete 
    data; or create new accounts with full user rights.
    (CVE-2017-8641)

  - A remote code execution vulnerability exists when Internet 
    Explorer improperly accesses objects in memory. The vulnerability 
    could corrupt memory in such a way that an attacker could execute 
    arbitrary code in the context of the current user.
    (CVE-2017-8651)

  - A remote code execution vulnerability exists when Microsoft 
    browsers improperly access objects in memory. The vulnerability 
    could corrupt memory in such a way that enables an attacker to 
    execute arbitrary code in the context of the current user.
    (CVE-2017-8653)

  - An information disclosure vulnerability exists when the win32k 
    component improperly provides kernel information. An attacker 
    who successfully exploited the vulnerability could obtain 
    information to further compromise the user's system.
    (CVE-2017-8666)

  - An information disclosure vulnerability exists when the Volume
    Manager Extension Drivercomponent improperly provides kernel
    information. An attacker who successfully exploited the
    vulnerability could obtain information to further compromise the
    users system. To exploit this vulnerability, an attacker would
    have to log on to an affected system and run a specially crafted
    application. The security update addresses the vulnerability by
    correcting how Volume Manager Extension Driver handles objects in
    memory. (CVE-2017-8668)

  - A remote code execution vulnerability exists when the Windows font
    library improperly handles specially crafted embedded fonts. An
    attacker who successfully exploited this vulnerability
    would gain code execution on the target system. Users whose
    accounts are configured to have fewer user rights on the system
    could be less impacted than users who operate with administrative
    user rights. There are multiple ways an attacker could exploit the
    vulnerability: In a web-based attack scenario, an attacker could
    host a specially crafted website that is designed to exploit the
    vulnerability and then convince users to view the website. An
    attacker would have no way to force users to view the
    attacker-controlled content. Instead, an attacker would have to
    convince users to take action, typically by getting them to click
    a link in an email or Instant Messenger message that takes users
    to the attacker's website, or by opening an attachment sent
    through email. In a file sharing attack scenario, an attacker
    could provide a specially crafted document file that is designed
    to exploit the vulnerability, and then convince users to open the
    document file. The security update addresses the vulnerability by
    correcting how the Windows font library handles embedded fonts.
    (CVE-2017-8691)");
  # https://support.microsoft.com/en-us/help/4022750/windows-netbios-denial-of-service-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8637e23a");
  # https://support.microsoft.com/en-us/help/4034034/windows-search-remote-code-execution-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a746ad8c");
  # https://support.microsoft.com/en-us/help/4034744/volume-manager-extension-driver-information-disclosure-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc718255");
  # https://support.microsoft.com/en-us/help/4034745/windows-clfs-elevation-of-privilege-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c9d1ae23");
  # https://support.microsoft.com/en-us/help/4034775/microsoft-jet-database-engine-remote-code-exec-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba9f2db3");
  # https://support.microsoft.com/en-us/help/4035055/win32k-information-disclosure-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd93e10f");
  # https://support.microsoft.com/en-us/help/4035056/express-compressed-fonts-remote-code-execution-vulnerability-in-window
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c83b0e2e");
  # https://support.microsoft.com/en-us/help/4035679/windows-error-reporting-elevation-of-privilege-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7fc780d");
  script_set_attribute(attribute:"solution", value:
"Apply the following security updates :

  - KB4022750
  - KB4034034
  - KB4034733
  - KB4034741
  - KB4034744 
  - KB4034745
  - KB4034775
  - KB4035055 
  - KB4035056
  - KB4035679");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8691");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS17-08';

kbs = make_list(
    "4035679",
    "4035056",
    "4035055",
    "4034775",
    "4034745",
    "4034744",
    "4034741",
    "4034733",
    "4034034",
    "4022750"
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

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

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

# 4035679
files = list_dir(basedir:winsxs, level:0, dir_pat:"errorreportingcore_31bf3856ad364e35", file_pat:"^wer\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.19848','6.0.6002.24169'),
                            max_versions:make_list('6.0.6002.20000','6.0.6002.99998'),
                            bulletin:bulletin,
                            kb:"4035679", session:the_session);

# 4035056
files = list_dir(basedir:winsxs, level:0, dir_pat:"font-embedding_31bf3856ad364e35", file_pat:"^t2embed\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.19834','6.0.6002.24154'),
                            max_versions:make_list('6.0.6002.20000','6.0.6002.99998'),
                            bulletin:bulletin,
                            kb:"4035056", session:the_session);

# 4035055
files = list_dir(basedir:winsxs, level:0, dir_pat:"win32k_31bf3856ad364e35", file_pat:"^win32k\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.19836','6.0.6002.24157'),
                            max_versions:make_list('6.0.6002.20000','6.0.6002.99998'),
                            bulletin:bulletin,
                            kb:"4035055", session:the_session);

# 4034775
files = list_dir(basedir:winsxs, level:0, dir_pat:"components-jetcore_31bf3856ad364e35", file_pat:"^msjet40\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('4.0.9801.0'),
                            max_versions:make_list('4.0.9801.10000'),
                            bulletin:bulletin,
                            kb:"4034775", session:the_session);

# 4034745
files = list_dir(basedir:winsxs, level:0, dir_pat:"commonlog_31bf3856ad364e35", file_pat:"^clfs\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.19837', '6.0.6002.24158'),
                            max_versions:make_list('6.0.6002.20000','6.0.6002.99998'),
                            bulletin:bulletin,
                            kb:"4034745", session:the_session);

# 4034744
files = list_dir(basedir:winsxs, level:0, dir_pat:"dynamicvolumemanager_31bf3856ad364e35", file_pat:"^volmgrx\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.19834', '6.0.6002.24154'),
                            max_versions:make_list('6.0.6002.20000','6.0.6002.99998'),
                            bulletin:bulletin,
                            kb:"4034744", session:the_session);

# 4034034
files = list_dir(basedir:winsxs, level:0, dir_pat:"indexing-common_31bf3856ad364e35", file_pat:"^query\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.19836', '6.0.6002.24154'),
                            max_versions:make_list('6.0.6002.20000','6.0.6002.99998'),
                            bulletin:bulletin,
                            kb:"4034034", session:the_session);

# 4022750
files = list_dir(basedir:winsxs, level:0, dir_pat:"tdi-over-tcpip_31bf3856ad364e35", file_pat:"^tdx\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.19832', '6.0.6002.24152'),
                            max_versions:make_list('6.0.6002.20000','6.0.6002.99998'),
                            bulletin:bulletin,
                            kb:"4022750", session:the_session);

# 4034741
if(
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntoskrnl.exe", version:"6.0.6002.19834", min_version:"6.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:"4034741") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntoskrnl.exe", version:"6.0.6002.24154", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"4034741")
  )
  vuln++;

# 4034733
if(
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21040", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"4034733") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.16929", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"4034733")
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
