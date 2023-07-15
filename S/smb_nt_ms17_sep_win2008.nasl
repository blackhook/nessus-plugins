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
  script_id(103140);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2017-8628",
    "CVE-2017-8675",
    "CVE-2017-8676",
    "CVE-2017-8678",
    "CVE-2017-8679",
    "CVE-2017-8680",
    "CVE-2017-8681",
    "CVE-2017-8682",
    "CVE-2017-8683",
    "CVE-2017-8684",
    "CVE-2017-8685",
    "CVE-2017-8687",
    "CVE-2017-8688",
    "CVE-2017-8695",
    "CVE-2017-8696",
    "CVE-2017-8699",
    "CVE-2017-8707",
    "CVE-2017-8708",
    "CVE-2017-8709",
    "CVE-2017-8710",
    "CVE-2017-8719",
    "CVE-2017-8720",
    "CVE-2017-8733",
    "CVE-2017-8741",
    "CVE-2017-8759"
  );
  script_bugtraq_id(
    100720,
    100722,
    100724,
    100727,
    100736,
    100737,
    100742,
    100744,
    100752,
    100755,
    100756,
    100764,
    100769,
    100772,
    100773,
    100780,
    100781,
    100782,
    100783,
    100790,
    100791,
    100792,
    100793,
    100803,
    100804
  );
  script_xref(name:"MSKB", value:"4032201");
  script_xref(name:"MSKB", value:"4034786");
  script_xref(name:"MSKB", value:"4038874");
  script_xref(name:"MSKB", value:"4039038");
  script_xref(name:"MSKB", value:"4039266");
  script_xref(name:"MSKB", value:"4039325");
  script_xref(name:"MSKB", value:"4039384");
  script_xref(name:"MSFT", value:"MS17-4032201");
  script_xref(name:"MSFT", value:"MS17-4034786");
  script_xref(name:"MSFT", value:"MS17-4038874");
  script_xref(name:"MSFT", value:"MS17-4039038");
  script_xref(name:"MSFT", value:"MS17-4039266");
  script_xref(name:"MSFT", value:"MS17-4039325");
  script_xref(name:"MSFT", value:"MS17-4039384");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Windows 2008 September 2017 Multiple Security Updates");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing multiple security updates released
on 2017/09/12. It is, therefore, affected by multiple
vulnerabilities :

  - An information disclosure vulnerability exists when
    Windows Hyper-V on a host operating system fails to
    properly validate input from an authenticated user on a
    guest operating system. To exploit the vulnerability, an
    attacker on a guest operating system could run a
    specially crafted application that could cause the
    Hyper-V host operating system to disclose memory
    information. An attacker who successfully exploited the
    vulnerability could gain access to information on the
    Hyper-V host operating system. The security update
    addresses the vulnerability by correcting how Hyper-V
    validates guest operating system user input.
    (CVE-2017-8707)

  - An information disclosure vulnerability exists in the
    Windows System Information Console when it improperly
    parses XML input containing a reference to an external
    entity. An attacker who successfully exploited this
    vulnerability could read arbitrary files via an XML
    external entity (XXE) declaration. To exploit the
    vulnerability, an attacker could create a file
    containing specially crafted XML content and convince an
    authenticated user to open the file. The update
    addresses the vulnerability by modifying the way that
    the Windows System Information Console parses XML input.
    (CVE-2017-8710)

  - An Information disclosure vulnerability exists in
    Windows kernel that could allow an attacker to retrieve
    information that could lead to a Kernel Address Space
    Layout Randomization (KASLR) bypass. An attacker who
    successfully exploited this vulnerability could retrieve
    the memory address of a kernel object. To exploit this
    vulnerability, an attacker would have to log on to an
    affected system and run a specially crafted application.
    The security update addresses the vulnerability by
    correcting how the Windows kernel handles memory
    addresses. (CVE-2017-8687)

  - An information disclosure vulnerability exists when the
    Microsoft Windows Graphics Component improperly handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could obtain information to
    further compromise the users system. To exploit this
    vulnerability, an attacker would have to log on to an
    affected system and run a specially crafted application.
    The vulnerability would not allow an attacker to execute
    code or to elevate user rights directly, but it could be
    used to obtain information that could be used to try to
    further compromise the affected system. The update
    addresses the vulnerability by correcting the way in
    which the Windows Graphics Component handles objects in
    memory. (CVE-2017-8683)

  - A remote code execution vulnerability exists when the
    Windows font library improperly handles specially
    crafted embedded fonts. An attacker who successfully
    exploited this vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights. Users whose accounts are
    configured to have fewer user rights on the system could
    be less impacted than users who operate with
    administrative user rights. There are multiple ways an
    attacker could exploit this vulnerability. In a web-
    based attack scenario, an attacker could host a
    specially crafted website that is designed to exploit
    this vulnerability and then convince a user to view the
    website. An attacker would have no way to force users to
    view the attacker-controlled content. Instead, an
    attacker would have to convince users to take action,
    typically by getting them to click a link in an email
    message or in an Instant Messenger message that takes
    users to the attacker's website, or by opening an
    attachment sent through email. In a file sharing attack
    scenario, an attacker could provide a specially crafted
    document file that is designed to exploit this
    vulnerability, and then convince a user to open the
    document file. The security update addresses the
    vulnerabilities by correcting how the Windows font
    library handles embedded fonts. (CVE-2017-8682)

  - A remote code execution vulnerability exists when
    Windows Shell does not properly validate file copy
    destinations. An attacker who successfully exploited the
    vulnerability could run arbitrary code in the context of
    the current user. If the current user is logged on with
    administrative user rights, an attacker could take
    control of the affected system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights. Users whose
    accounts are configured to have fewer user rights on the
    system could be less impacted than users who operate
    with administrative user rights. To exploit the
    vulnerability, a user must open a specially crafted
    file. In an email attack scenario, an attacker could
    exploit the vulnerability by sending the specially
    crafted file to the user and then convincing the user to
    open the file. In a web-based attack scenario, an
    attacker could host a website (or leverage a compromised
    website that accepts or hosts user-provided content)
    that contains a specially crafted file designed to
    exploit the vulnerability. An attacker would have no way
    to force a user to visit the website. Instead, an
    attacker would have to convince a user to click a link,
    typically by way of an enticement in an email or Instant
    Messenger message, and then convince the user to open
    the specially crafted file. The security update
    addresses the vulnerability by helping to ensure that
    Windows Shell validates file copy destinations.
    (CVE-2017-8699)

  - An information disclosure vulnerability exists when the
    Windows kernel fails to properly initialize a memory
    address, allowing an attacker to retrieve information
    that could lead to a Kernel Address Space Layout
    Randomization (KASLR) bypass. An attacker who
    successfully exploited this vulnerability could retrieve
    the base address of the kernel driver from a compromised
    process. To exploit this vulnerability, an attacker
    would have to log on to an affected system and run a
    specially crafted application. The security update
    addresses the vulnerability by correcting how the
    Windows kernel handles memory addresses. (CVE-2017-8708)

  - An information disclosure vulnerability exists when
    Windows Uniscribe improperly discloses the contents of
    its memory. An attacker who successfully exploited the
    vulnerability could obtain information to further
    compromise the users system. There are multiple ways an
    attacker could exploit the vulnerability, such as by
    convincing a user to open a specially crafted document
    or by convincing a user to visit an untrusted webpage.
    The update addresses the vulnerability by correcting how
    Windows Uniscribe handles objects in memory.
    (CVE-2017-8695)

  - An elevation of privilege vulnerability exists in
    Windows when the Win32k component fails to properly
    handle objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights. To exploit this vulnerability, an
    attacker would first have to log on to the system. An
    attacker could then run a specially crafted application
    that could exploit the vulnerability and take control of
    an affected system. The update addresses this
    vulnerability by correcting how Win32k handles objects
    in memory. (CVE-2017-8720)

  - A information disclosure vulnerability exists when the
    Windows GDI+ component improperly discloses kernel
    memory addresses. An attacker who successfully exploited
    the vulnerability could obtain information to further
    compromise the users system. To exploit this
    vulnerability, an attacker would have to log on to an
    affected system and run a specially crafted application.
    The vulnerability would not allow an attacker to execute
    code or to elevate user rights directly, but it could be
    used to obtain information that could be used to try to
    further compromise the affected system. The security
    update addresses the vulnerability by correcting how the
    Windows GDI+ component handles objects in memory.
    (CVE-2017-8680, CVE-2017-8681, CVE-2017-8684,
    CVE-2017-8685)

  - A remote code execution vulnerability exists due to the
    way Windows Uniscribe handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could take control of the affected system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    Users whose accounts are configured to have fewer user
    rights on the system could be less impacted than users
    who operate with administrative user rights. There are
    multiple ways an attacker could exploit this
    vulnerability: In a web-based attack scenario, an
    attacker could host a specially crafted website designed
    to exploit this vulnerability and then convince a user
    to view the website. An attacker would have no way to
    force users to view the attacker-controlled content.
    Instead, an attacker would have to convince users to
    take action, typically by getting them to click a link
    in an email or instant message that takes users to the
    attacker's website, or by opening an attachment sent
    through email. In a file-sharing attack scenario, an
    attacker could provide a specially crafted document file
    designed to exploit this vulnerability and then convince
    a user to open the document file.The security update
    addresses the vulnerability by correcting how Windows
    Uniscribe handles objects in memory. (CVE-2017-8696)

  - An information disclosure vulnerability exists in the
    way that the Windows Graphics Device Interface+ (GDI+)
    handles objects in memory, allowing an attacker to
    retrieve information from a targeted system. By itself,
    the information disclosure does not allow arbitrary code
    execution; however, it could allow arbitrary code to be
    run if the attacker uses it in combination with another
    vulnerability. To exploit this vulnerability, an
    attacker would have to log on to an affected system and
    run a specially crafted application. The security update
    addresses the vulnerability by correcting how GDI+
    handles memory addresses. (CVE-2017-8688)

  - An elevation of privilege vulnerability exists in
    Windows when the Windows kernel-mode driver fails to
    properly handle objects in memory. An attacker who
    successfully exploited this vulnerability could run
    arbitrary code in kernel mode. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights. To exploit
    this vulnerability, an attacker would first have to log
    on to the system. An attacker could then run a specially
    crafted application that could exploit the vulnerability
    and take control of an affected system. The update
    addresses this vulnerability by correcting how the
    Windows kernel-mode driver handles objects in memory.
    (CVE-2017-8675)

  - A spoofing vulnerability exists in Microsoft's
    implementation of the Bluetooth stack. An attacker who
    successfully exploited this vulnerability could perform
    a man-in-the-middle attack and force a user's computer
    to unknowingly route traffic through the attacker's
    computer. The attacker can then monitor and read the
    traffic before sending it on to the intended recipient.
    To exploit the vulnerability, the attacker needs to be
    within the physical proximity of the targeted user, and
    the user's computer needs to have Bluetooth enabled. The
    attacker can then initiate a Bluetooth connection to the
    target computer without the user's knowledge. The
    security update addresses the vulnerability by
    correcting how Windows handles Bluetooth requests.
    (CVE-2017-8628)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system. To exploit this vulnerability, an attacker would
    have to log on to an affected system and run a specially
    crafted application. The vulnerability would not allow
    an attacker to execute code or to elevate user rights
    directly, but it could be used to obtain information
    that could be used to try to further compromise the
    affected system. The update addresses the vulnerability
    by correcting how the Windows kernel handles objects in
    memory. (CVE-2017-8678, CVE-2017-8679, CVE-2017-8709,
    CVE-2017-8719)

  - An information disclosure vulnerability exists in the
    way that the Windows Graphics Device Interface (GDI)
    handles objects in memory, allowing an attacker to
    retrieve information from a targeted system. By itself,
    the information disclosure does not allow arbitrary code
    execution; however, it could allow arbitrary code to be
    run if the attacker uses it in combination with another
    vulnerability. To exploit this vulnerability, an
    attacker would have to log on to an affected system and
    run a specially crafted application. Note that where the
    severity is indicated as Critical in the Affected
    Products table, the Preview Pane is an attack vector for
    this vulnerability. The security update addresses the
    vulnerability by correcting how GDI handles memory
    addresses. (CVE-2017-8676)");
  # https://support.microsoft.com/en-us/help/4032201/windows-kernel-information-disclosure-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4cfaff8");
  # https://support.microsoft.com/en-us/help/4034786/bluetooth-driver-spoofing-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a43fdc7");
  # https://support.microsoft.com/en-us/help/4038874/windows-kernel-information-disclosure-vulnerability-in-windows-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c6e0c59");
  # https://support.microsoft.com/en-us/help/4039038/information-disclosure-vulnerability-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28782454");
  # https://support.microsoft.com/en-us/help/4039266/windows-shell-remote-code-execution-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2d3ffe7");
  # https://support.microsoft.com/en-us/help/4039325/hyper-v-information-disclosure-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09206238");
  # https://support.microsoft.com/en-us/help/4039384/windows-uniscribe-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d820c79");
  script_set_attribute(attribute:"solution", value:
"Apply the following security updates :

  - KB4032201
  - KB4034786
  - KB4038874
  - KB4039038
  - KB4039266
  - KB4039325
  - KB4039384");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8759");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-8682");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  "4032201",
  "4034786",
  "4038874",
  "4039038",
  "4039266",
  "4039325",
  "4039384"
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

# 4032201
files = list_dir(basedir:winsxs, level:0, dir_pat:"-usermodensi_31bf3856ad364e35", file_pat:"^nsisvc\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.19858','6.0.6002.24180'),
                            max_versions:make_list('6.0.6002.20000','6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4032201", session:the_session);

# 4034786 ; cannot locate on disk yet
files = list_dir(basedir:winsxs, level:0, dir_pat:"bthpan.inf_31bf3856ad364e35", file_pat:"^bthpan\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.19848','6.0.6002.24169'),
                            max_versions:make_list('6.0.6002.20000','6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4034786", session:the_session);

# 4038874
files = list_dir(basedir:winsxs, level:0, dir_pat:"ntdll_31bf3856ad364e35", file_pat:"^ntdll\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.19623','6.0.6002.24180'),
                            max_versions:make_list('6.0.6002.20000','6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4038874", session:the_session);

# 4039038
files = list_dir(basedir:winsxs, level:0, dir_pat:"m..-management-console_31bf3856ad364e35", file_pat:"^mmc\.exe$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.19858', '6.0.6002.24180'),
                            max_versions:make_list('6.0.6002.20000','6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4039038", session:the_session);

# 4039266
files = list_dir(basedir:winsxs, level:0, dir_pat:"shell32_31bf3856ad364e35", file_pat:"^shell32\.dll$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.19861', '6.0.6002.24182'),
                            max_versions:make_list('6.0.6002.20000','6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4039266", session:the_session);

# 4039325 ; x64 only ; hyper-v
#arch = get_kb_item_or_exit('SMB/ARCH');
#if (arch == "x64")
#{
#  files = list_dir(basedir:winsxs, level:0, dir_pat:"vstack-vmwp_31bf3856ad364e35", file_pat:"^vmwp\.exe$", max_recurse:1);
#  vuln += hotfix_check_winsxs(os:'6.0',
#                              sp:2,
#                              files:files,
#                              versions:make_list('6.0.6002.19858', '6.0.6002.24180'),
#                              max_versions:make_list('6.0.6002.20000','6.0.6003.99999'),
#                              bulletin:bulletin,
#                              kb:"4039325", session:the_session);
#}

# 4039384
files = list_dir(basedir:winsxs, level:0, dir_pat:"win32k_31bf3856ad364e35", file_pat:"^win32k\.sys$", max_recurse:1);
vuln += hotfix_check_winsxs(os:'6.0',
                            sp:2,
                            files:files,
                            versions:make_list('6.0.6002.19836', '6.0.6002.24154'),
                            max_versions:make_list('6.0.6002.20000','6.0.6003.99999'),
                            bulletin:bulletin,
                            kb:"4039384", session:the_session);

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
