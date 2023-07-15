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
  script_id(140415);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/08");

  script_cve_id(
    "CVE-2020-0648",
    "CVE-2020-0766",
    "CVE-2020-0782",
    "CVE-2020-0790",
    "CVE-2020-0805",
    "CVE-2020-0837",
    "CVE-2020-0838",
    "CVE-2020-0839",
    "CVE-2020-0875",
    "CVE-2020-0878",
    "CVE-2020-0886",
    "CVE-2020-0890",
    "CVE-2020-0904",
    "CVE-2020-0908",
    "CVE-2020-0911",
    "CVE-2020-0912",
    "CVE-2020-0914",
    "CVE-2020-0921",
    "CVE-2020-0922",
    "CVE-2020-0928",
    "CVE-2020-0941",
    "CVE-2020-0951",
    "CVE-2020-0989",
    "CVE-2020-0997",
    "CVE-2020-0998",
    "CVE-2020-1012",
    "CVE-2020-1013",
    "CVE-2020-1030",
    "CVE-2020-1031",
    "CVE-2020-1033",
    "CVE-2020-1034",
    "CVE-2020-1038",
    "CVE-2020-1039",
    "CVE-2020-1052",
    "CVE-2020-1053",
    "CVE-2020-1057",
    "CVE-2020-1074",
    "CVE-2020-1083",
    "CVE-2020-1091",
    "CVE-2020-1097",
    "CVE-2020-1098",
    "CVE-2020-1115",
    "CVE-2020-1119",
    "CVE-2020-1122",
    "CVE-2020-1129",
    "CVE-2020-1130",
    "CVE-2020-1133",
    "CVE-2020-1146",
    "CVE-2020-1152",
    "CVE-2020-1159",
    "CVE-2020-1169",
    "CVE-2020-1172",
    "CVE-2020-1180",
    "CVE-2020-1245",
    "CVE-2020-1250",
    "CVE-2020-1252",
    "CVE-2020-1256",
    "CVE-2020-1285",
    "CVE-2020-1303",
    "CVE-2020-1308",
    "CVE-2020-1319",
    "CVE-2020-1376",
    "CVE-2020-1471",
    "CVE-2020-1491",
    "CVE-2020-1506",
    "CVE-2020-1507",
    "CVE-2020-1508",
    "CVE-2020-1532",
    "CVE-2020-1559",
    "CVE-2020-1589",
    "CVE-2020-1590",
    "CVE-2020-1592",
    "CVE-2020-1593",
    "CVE-2020-1596",
    "CVE-2020-1598",
    "CVE-2020-16854",
    "CVE-2020-16879"
  );
  script_xref(name:"MSKB", value:"4571756");
  script_xref(name:"MSFT", value:"MS20-4571756");
  script_xref(name:"IAVA", value:"2020-A-0408-S");
  script_xref(name:"IAVA", value:"2020-A-0409-S");
  script_xref(name:"IAVA", value:"2020-A-0417-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0118");

  script_name(english:"KB4571756: Windows 10 Version 2004 September 2020 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4571756.
It is, therefore, affected by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists when
    DirectX improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could run arbitrary code in kernel mode. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2020-1053, CVE-2020-1308)

  - An elevation of privilege vulnerability exists when the
    Windows RSoP Service Application improperly handles
    memory.  (CVE-2020-0648)

  - A remote code execution vulnerability exists in the way
    that the Windows Graphics Device Interface (GDI) handles
    objects in the memory. An attacker who successfully
    exploited this vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2020-1285)

  - An elevation of privilege vulnerability exists in the
    way that Microsoft COM for Windows handles objects in
    memory. An attacker who successfully exploited the
    vulnerability could gain elevated privileges on a
    targeted system.  (CVE-2020-1507)

  - An information disclosure vulnerability exists when the
    Windows GDI component improperly discloses the contents
    of its memory. An attacker who successfully exploited
    the vulnerability could obtain information to further
    compromise the users system. There are multiple ways an
    attacker could exploit the vulnerability, such as by
    convincing a user to open a specially crafted document,
    or by convincing a user to visit an untrusted webpage.
    The security update addresses the vulnerability by
    correcting how the Windows GDI component handles objects
    in memory. (CVE-2020-1256)

  - An information disclosure vulnerability exists in how
    splwow64.exe handles certain calls. An attacker who
    successfully exploited this vulnerability could obtain
    information to further compromise the users system (low-
    integrity to medium-integrity). This vulnerability by
    itself does not allow arbitrary code execution; however,
    it could allow arbitrary code to be run if the attacker
    uses it in combination with another vulnerability (such
    as a remote code execution vulnerability or another
    elevation of privilege vulnerability) that is capable of
    leveraging the elevated privileges when code execution
    is attempted. The security update addresses the
    vulnerability by ensuring splwow64.exe properly handles
    these calls. (CVE-2020-0875)

  - An elevation of privilege vulnerability exists when
    Microsoft Windows CloudExperienceHost fails to check COM
    objects. An attacker who successfully exploited the
    vulnerability could gain elevated privileges on a
    targeted system.  (CVE-2020-1471)

  - An information disclosure vulnerability exists when the
    Microsoft Windows Graphics Component improperly handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could obtain information to
    further compromise the users system.  (CVE-2020-0921,
    CVE-2020-1083)

  - An elevation of privilege vulnerability exists in
    Windows when the Win32k component fails to properly
    handle objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2020-1245)

  - An elevation of privilege vulnerability exists in the
    way that the dnsrslvr.dll handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2020-0839)

  - An elevation of privilege vulnerability exists when the
    Diagnostics Hub Standard Collector improperly handles
    file operations. An attacker who successfully exploited
    this vulnerability could run processes in an elevated
    context. An attacker could exploit this vulnerability by
    running a specially crafted application on the victim
    system. The update addresses the vulnerability by
    correcting the way the Diagnostics Hub Standard
    Collector handles file operations. (CVE-2020-1133)

  - An elevation of privilege vulnerability exists when the
    Windows Storage Services improperly handle file
    operations. An attacker who successfully exploited this
    vulnerability could gain elevated privileges.
    (CVE-2020-0886, CVE-2020-1559)

  - An information disclosure vulnerability exists when the
    Windows GDI component improperly discloses the contents
    of its memory. An attacker who successfully exploited
    the vulnerability could obtain information to further
    compromise a users system. There are multiple ways an
    attacker could exploit the vulnerability, such as by
    convincing a user to open a specially crafted document
    or by convincing a user to visit an untrusted webpage.
    The update addresses the vulnerability by correcting how
    the Windows GDI component handles objects in memory.
    (CVE-2020-1091, CVE-2020-1097)

  - A remote code execution vulnerability exists when
    Windows Media Audio Decoder improperly handles objects.
    An attacker who successfully exploited the vulnerability
    could take control of an affected system. There are
    multiple ways an attacker could exploit the
    vulnerability, such as by convincing a user to open a
    specially crafted document, or by convincing a user to
    visit a malicious webpage. The security update addresses
    the vulnerability by correcting how Windows Media Audio
    Decoder handles objects. (CVE-2020-1508, CVE-2020-1593)

  - An elevation of privilege vulnerability exists when the
    Microsoft Store Runtime improperly handles memory.
    (CVE-2020-0766, CVE-2020-1146)

  - A remote code execution vulnerability exists when the
    Windows Jet Database Engine improperly handles objects
    in memory. An attacker who successfully exploited this
    vulnerability could execute arbitrary code on a victim
    system. An attacker could exploit this vulnerability by
    enticing a victim to open a specially crafted file. The
    update addresses the vulnerability by correcting the way
    the Windows Jet Database Engine handles objects in
    memory. (CVE-2020-1039, CVE-2020-1074)

  - An information disclosure vulnerability exists when the
    win32k component improperly provides kernel information.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2020-1250)

  - An elevation of privilege vulnerability exists in the
    way that the ssdpsrv.dll handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2020-1052)

  - An information disclosure vulnerability exists when the
    Windows State Repository Service improperly handles
    objects in memory. An attacker who successfully
    exploited this vulnerability could obtain information to
    further compromise the users system. An attacker could
    exploit this vulnerability by running a specially
    crafted application on the victim system. The update
    addresses the vulnerability by correcting the way the
    Windows State Repository Service handles objects in
    memory. (CVE-2020-0914)

  - An elevation of privilege vulnerability exists in the
    way that the Wininit.dll handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could execute code with elevated permissions. There are
    multiple ways an attacker could exploit the
    vulnerability:  (CVE-2020-1012, CVE-2020-1506)

  - An elevation of privilege vulnerability exists when the
    Windows Runtime improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could run arbitrary code in an elevated context. An
    attacker could exploit this vulnerability by running a
    specially crafted application on the victim system. The
    update addresses the vulnerability by correcting the way
    the Windows Runtime handles objects in memory.
    (CVE-2020-1169, CVE-2020-1303)

  - A remote code execution vulnerability exists in the way
    that Microsoft Windows Codecs Library handles objects in
    memory. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system. Exploitation of the
    vulnerability requires that a program process a
    specially crafted image file. The update addresses the
    vulnerability by correcting how Microsoft Windows Codecs
    Library handles objects in memory. (CVE-2020-1129)

  - An elevation of privilege vulnerability exists when the
    Windows Print Spooler service improperly allows
    arbitrary writing to the file system. An attacker who
    successfully exploited this vulnerability could run
    arbitrary code with elevated system privileges. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts with full user
    rights.  (CVE-2020-1030)

  - An information disclosure vulnerability exists when a
    Windows Projected Filesystem improperly handles file
    redirections. An attacker who successfully exploited
    this vulnerability could obtain information to further
    compromise the user's system  (CVE-2020-16879)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2020-0928, CVE-2020-1589, CVE-2020-16854)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly initializes objects in memory.
    (CVE-2020-1592)

  - An elevation of privilege vulnerability exists when the
    Windows Function Discovery SSDP Provider improperly
    handles memory.  (CVE-2020-0912)

  - A denial of service vulnerability exists when Windows
    Routing Utilities improperly handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could cause a target system to stop responding.
    (CVE-2020-1038)

  - A remote code execution vulnerability exists when
    Windows improperly handles objects in memory.
    (CVE-2020-1252)

  - An elevation of privilege vulnerability exists when the
    Windows InstallService improperly handles memory.
    (CVE-2020-1532)

  - A local elevation of privilege vulnerability exists in
    how splwow64.exe handles certain calls. An attacker who
    successfully exploited the vulnerability could elevate
    privileges on an affected system from low-integrity to
    medium-integrity. This vulnerability by itself does not
    allow arbitrary code execution; however, it could allow
    arbitrary code to be run if the attacker uses it in
    combination with another vulnerability (such as a remote
    code execution vulnerability or another elevation of
    privilege vulnerability) that is capable of leveraging
    the elevated privileges when code execution is
    attempted. The security update addresses the
    vulnerability by ensuring splwow64.exe properly handles
    these calls.. (CVE-2020-0790)

  - A security feature bypass vulnerability exists when a
    Windows Projected Filesystem improperly handles file
    redirections. An attacker who successfully exploited
    this vulnerability could delete a targeted file they
    would not have permissions to.  (CVE-2020-0805)

  - An elevation of privilege vulnerability exists when the
    Windows Cryptographic Catalog Services improperly handle
    objects in memory. An attacker who successfully
    exploited this vulnerability could modify the
    cryptographic catalog.  (CVE-2020-0782)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system. An authenticated attacker could exploit this
    vulnerability by running a specially crafted
    application. The update addresses the vulnerability by
    correcting how the Windows kernel handles objects in
    memory. (CVE-2020-1033)

  - A denial of service vulnerability exists when Microsoft
    Hyper-V on a host server fails to properly validate
    specific malicious data from a user on a guest operating
    system.  (CVE-2020-0890, CVE-2020-0904)

  - A remote code execution vulnerability exists in the way
    that Microsoft Windows Codecs Library handles objects in
    memory. An attacker who successfully exploited this
    vulnerability could take control of the affected system.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights. Exploitation of the vulnerability requires that
    a program process a specially crafted image file. The
    update addresses the vulnerability by correcting how
    Microsoft Windows Codecs Library handles objects in
    memory. (CVE-2020-1319)

  - An information disclosure vulnerability exists in the
    way that the Windows Server DHCP service improperly
    discloses the contents of its memory.  (CVE-2020-1031)

  - A remote code execution vulnerability exists in the way
    that Microsoft COM for Windows handles objects in
    memory. An attacker who successfully exploited the
    vulnerability could execute arbitrary code on a target
    system.  (CVE-2020-0922)

  - An information disclosure vulnerability exists when the
    win32k component improperly provides kernel information.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2020-0941)

  - A remote code execution vulnerability exists when the
    Windows Text Service Module improperly handles memory.
    An attacker who successfully exploited the vulnerability
    could gain execution on a victim system. An attacker
    could host a specially crafted website that is designed
    to exploit the vulnerability through Microsoft Edge
    (Chromium-based), and then convince a user to view the
    website. The attacker could also take advantage of
    compromised websites and websites that accept or host
    user-provided content or advertisements by adding
    specially crafted content that could exploit the
    vulnerability. In all cases, however, an attacker would
    have no way to force users to view the attacker-
    controlled content. Instead, an attacker would have to
    convince users to take action, typically by way of
    enticement in an email or Instant Messenger message, or
    by getting them to open an attachment sent through
    email. The security update addresses the vulnerability
    by correcting how the Windows Text Service Module
    handles memory. (CVE-2020-0908)

  - A remote code execution vulnerability exists in the way
    that the ChakraCore scripting engine handles objects in
    memory. The vulnerability could corrupt memory in such a
    way that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2020-1057,
    CVE-2020-1172, CVE-2020-1180)

  - A information disclosure vulnerability exists when TLS
    components use weak hash algorithms. An attacker who
    successfully exploited this vulnerability could obtain
    information to further compromise a users's encrypted
    transmission channel.  (CVE-2020-1596)

  - An elevation of privilege vulnerability exists in the
    way that fdSSDP.dll handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2020-1376)

  - An elevation of privilege vulnerability exists when
    Windows improperly handles calls to Win32k.sys. An
    attacker who successfully exploited the vulnerability
    could gain elevated privileges on a targeted system.
    (CVE-2020-1152)

  - A remote code execution vulnerability exists when the
    Windows Camera Codec Pack improperly handles objects in
    memory. An attacker who successfully exploited the
    vulnerability could run arbitrary code in the context of
    the current user. If the current user is logged on with
    administrative user rights, an attacker could take
    control of the affected system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2020-0997)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Kernel handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2020-1034)

  - An elevation of privilege vulnerability exists when the
    Windows Common Log File System (CLFS) driver improperly
    handles objects in memory. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context.  (CVE-2020-1115)

  - An information disclosure vulnerability exists when
    Windows Mobile Device Management (MDM) Diagnostics
    improperly handles junctions. An attacker who
    successfully exploited this vulnerability could bypass
    access restrictions to read files.  (CVE-2020-0989)

  - A remote code execution vulnerability exists in the way
    that Microsoft browsers access objects in memory. The
    vulnerability could corrupt memory in a way that could
    allow an attacker to execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2020-0878)

  - A security feature bypass vulnerability exists in
    Windows Defender Application Control (WDAC) which could
    allow an attacker to bypass WDAC enforcement. An
    attacker who successfully exploited this vulnerability
    could execute PowerShell commands that would be blocked
    by WDAC.  (CVE-2020-0951)

  - An elevation of privilege vulnerability exists when
    Microsoft Windows processes group policy updates. An
    attacker who successfully exploited this vulnerability
    could potentially escalate permissions or perform
    additional privileged actions on the target machine.
    (CVE-2020-1013)

  - An elevation of privilege vulnerability exists when the
    Windows Universal Plug and Play (UPnP) service
    improperly handles objects in memory. An attacker who
    successfully exploited this vulnerability could run
    arbitrary code with elevated system privileges. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts with full user
    rights.  (CVE-2020-1598)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Function Discovery Service handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could execute code with
    elevated permissions.  (CVE-2020-1491)

  - An elevation of privilege vulnerability exists when the
    Diagnostics Hub Standard Collector improperly handles
    data operations. An attacker who successfully exploited
    this vulnerability could run processes in an elevated
    context. An attacker could exploit this vulnerability by
    running a specially crafted application on the victim
    system. The update addresses the vulnerability by
    correcting the way the Diagnostics Hub Standard
    Collector handles data operations. (CVE-2020-1130)

  - An elevation of privilege vulnerability exists when
    Windows Modules Installer improperly handles objects in
    memory. An attacker who successfully exploited this
    vulnerability could run arbitrary code in an elevated
    context. An attacker could exploit this vulnerability by
    running a specially crafted application on the victim
    system. The update addresses the vulnerability by
    correcting the way the Windows Modules Installer handles
    objects in memory. (CVE-2020-0911)

  - An elevation of privilege vulnerability exists in the
    way that the StartTileData.dll handles file creation in
    protected locations. An attacker who successfully
    exploited the vulnerability could execute code with
    elevated permissions.  (CVE-2020-1159)

  - An elevation of privilege vulnerability exists when NTFS
    improperly checks access. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context.  (CVE-2020-0838)

  - An elevation of privilege vulnerability exists when the
    Connected User Experiences and Telemetry Service
    improperly handles file operations. An attacker who
    successfully exploited this vulnerability could gain
    elevated privileges on the victim system.
    (CVE-2020-1590)

  - An elevation of privilege vulnerability exists when the
    Windows Graphics Component improperly handles objects in
    memory. An attacker who successfully exploited this
    vulnerability could run processes in an elevated
    context.  (CVE-2020-0998)

  - An information disclosure vulnerability exists when
    StartTileData.dll improperly handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2020-1119)

  - An elevation of privilege vulnerability exists when the
    Windows Language Pack Installer improperly handles file
    operations. An attacker who successfully exploited this
    vulnerability could run processes in an elevated
    context. An attacker could exploit this vulnerability by
    running a specially crafted application on the victim
    system. The update addresses the vulnerability by
    correcting the way the Windows Language Pack Installer
    handles file operations. (CVE-2020-1122)

  - A spoofing vulnerability exists when Active Directory
    Federation Services (ADFS) improperly handles multi-
    factor authentication requests.  (CVE-2020-0837)

  - An elevation of privilege vulnerability exists when the
    Shell infrastructure component improperly handles
    objects in memory. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context.  (CVE-2020-1098)");
  # https://support.microsoft.com/en-us/help/4571756/windows-10-update-kb4571756
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?deaef255");
  script_set_attribute(attribute:"solution", value:
"Apply Cumulative Update KB4571756.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1508");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-1593");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS20-09";
kbs = make_list('4571756');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"19041",
                   rollup_date:"09_2020",
                   bulletin:bulletin,
                   rollup_kb_list:[4571756])
)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}



