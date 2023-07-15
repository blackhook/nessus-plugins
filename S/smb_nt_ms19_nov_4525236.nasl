#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130906);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/08");

  script_cve_id(
    "CVE-2018-12207",
    "CVE-2019-0712",
    "CVE-2019-0719",
    "CVE-2019-1374",
    "CVE-2019-1380",
    "CVE-2019-1381",
    "CVE-2019-1382",
    "CVE-2019-1383",
    "CVE-2019-1384",
    "CVE-2019-1388",
    "CVE-2019-1389",
    "CVE-2019-1390",
    "CVE-2019-1391",
    "CVE-2019-1393",
    "CVE-2019-1394",
    "CVE-2019-1395",
    "CVE-2019-1396",
    "CVE-2019-1397",
    "CVE-2019-1399",
    "CVE-2019-1405",
    "CVE-2019-1406",
    "CVE-2019-1407",
    "CVE-2019-1408",
    "CVE-2019-1409",
    "CVE-2019-1411",
    "CVE-2019-1413",
    "CVE-2019-1415",
    "CVE-2019-1417",
    "CVE-2019-1418",
    "CVE-2019-1419",
    "CVE-2019-1420",
    "CVE-2019-1422",
    "CVE-2019-1424",
    "CVE-2019-1426",
    "CVE-2019-1427",
    "CVE-2019-1428",
    "CVE-2019-1429",
    "CVE-2019-1433",
    "CVE-2019-1435",
    "CVE-2019-1436",
    "CVE-2019-1438",
    "CVE-2019-1439",
    "CVE-2019-1454",
    "CVE-2019-1456",
    "CVE-2019-11135"
  );
  script_xref(name:"MSKB", value:"4525236");
  script_xref(name:"MSFT", value:"MS19-4525236");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/05");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/28");

  script_name(english:"KB4525236: Windows 10 Version 1607 and Windows Server 2016 November 2019 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4525236. 
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists when 
    Windows Hyper-V Network Switch on a host server fails
    to properly validate input from an authenticated user
    on a guest operating system.  (CVE-2019-0719)

  - A remote code execution vulnerability exists when
    Windows Hyper-V on a host server fails to properly
    validate input from an authenticated user on a guest
    operating system.  (CVE-2019-1389, CVE-2019-1397)

  - A security feature bypass vulnerability exists when
    Windows Netlogon improperly handles a secure
    communications channel. An attacker who successfully
    exploited the vulnerability could downgrade aspects of
    the connection allowing for further modification of the
    transmission.  (CVE-2019-1424)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2019-11135)

  - An information disclosure vulnerability exists in the
    way Windows Error Reporting (WER) handles objects in
    memory. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2019-1374)

  - An elevation of privilege vulnerability exists in the
    Windows Certificate Dialog when it does not properly
    enforce user privileges. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context. An attacker could then install
    programs; view, change or delete data.  (CVE-2019-1388)

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
    these calls.. (CVE-2019-1380)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2019-1429)

  - A security feature bypass vulnerability exists where a
    NETLOGON message is able to obtain the session key and
    sign messages.  (CVE-2019-1384)

  - An elevation of privilege vulnerability exists when the
    Windows Graphics Component improperly handles objects in
    memory. An attacker who successfully exploited this
    vulnerability could run processes in an elevated
    context.  (CVE-2019-1407, CVE-2019-1433, CVE-2019-1435,
    CVE-2019-1438)

  - An information vulnerability exists when Windows Modules
    Installer Service improperly discloses file information.
    Successful exploitation of the vulnerability could allow
    the attacker to read the contents of a log file on disk.
    (CVE-2019-1418)

  - An elevation of privilege vulnerability exists when the
    Windows User Profile Service (ProfSvc) improperly
    handles symlinks. An attacker who successfully exploited
    this vulnerability could delete files and folders in an
    elevated context.  (CVE-2019-1454)

  - A denial of service vulnerability exists when Microsoft
    Hyper-V Network Switch on a host server fails to
    properly validate input from a privileged user on a
    guest operating system. An attacker who successfully
    exploited the vulnerability could cause the host server
    to crash.  (CVE-2019-0712)

  - A denial of service vulnerability exists when Windows
    improperly handles objects in memory. An attacker who
    successfully exploited the vulnerability could cause a
    target system to stop responding.  (CVE-2018-12207,
    CVE-2019-1391)

  - An elevation of privilege vulnerability exists in
    Windows when the Win32k component fails to properly
    handle objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2019-1393, CVE-2019-1394,
    CVE-2019-1395, CVE-2019-1396, CVE-2019-1408)

  - An elevation of privilege vulnerability exists in
    Windows Installer because of the way Windows Installer
    handles certain filesystem operations.  (CVE-2019-1415)

  - An information disclosure vulnerability exists when
    DirectWrite improperly discloses the contents of its
    memory. An attacker who successfully exploited the
    vulnerability could obtain information to further
    compromise the users system. There are multiple ways an
    attacker could exploit the vulnerability, such as by
    convincing a user to open a specially crafted document,
    or by convincing a user to visit an untrusted webpage.
    The security update addresses the vulnerability by
    correcting how DirectWrite handles objects in memory.
    (CVE-2019-1411)

  - An information disclosure vulnerability exists when the
    Windows Servicing Stack allows access to unprivileged
    file locations. An attacker who successfully exploited
    the vulnerability could potentially access unauthorized
    files.  (CVE-2019-1381)

  - A remote code execution vulnerability exists in the way
    that the VBScript engine handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2019-1390)

  - An information disclosure vulnerability exists when the
    win32k component improperly provides kernel information.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2019-1436)

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
    in memory. (CVE-2019-1439)

  - A remote code execution vulnerability exists when the
    Windows Jet Database Engine improperly handles objects
    in memory. An attacker who successfully exploited this
    vulnerability could execute arbitrary code on a victim
    system. An attacker could exploit this vulnerability by
    enticing a victim to open a specially crafted file. The
    update addresses the vulnerability by correcting the way
    the Windows Jet Database Engine handles objects in
    memory. (CVE-2019-1406)

  - An elevation of privilege vulnerability exists when the
    Windows Universal Plug and Play (UPnP) service
    improperly allows COM object creation. An attacker who
    successfully exploited this vulnerability could run
    arbitrary code with elevated system privileges. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts with full user
    rights.  (CVE-2019-1405)

  - A remote code execution vulnerability exists in
    Microsoft Windows when the Windows Adobe Type Manager
    Library improperly handles specially crafted OpenType
    fonts. For all systems except Windows 10, an attacker
    who successfully exploited the vulnerability could
    execute code remotely. For systems running Windows 10,
    an attacker who successfully exploited the vulnerability
    could execute code in an AppContainer sandbox context
    with limited privileges and capabilities. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    There are multiple ways an attacker could exploit the
    vulnerability, such as by either convincing a user to
    open a specially crafted document, or by convincing a
    user to visit a webpage that contains specially crafted
    embedded OpenType fonts. The update addresses the
    vulnerability by correcting how the Windows Adobe Type
    Manager Library handles OpenType fonts. (CVE-2019-1419,
    CVE-2019-1456)

  - A denial of service vulnerability exists when Microsoft
    Hyper-V on a host server fails to properly validate
    input from a privileged user on a guest operating
    system.  (CVE-2019-1399)

  - An elevation of privilege vulnerability exists when the
    Windows Data Sharing Service improperly handles file
    operations. An attacker who successfully exploited this
    vulnerability could run processes in an elevated
    context. An attacker could exploit this vulnerability by
    running a specially crafted application on the victim
    system. The update addresses the vulnerability by
    correcting the way the Windows Data Sharing Service
    handles file operations. (CVE-2019-1383, CVE-2019-1417)

  - An elevation of privilege vulnerability exists when
    ActiveX Installer service may allow access to files
    without proper authentication. An attacker who
    successfully exploited the vulnerability could
    potentially access unauthorized files.  (CVE-2019-1382)

  - An information disclosure vulnerability exists when the
    Windows Remote Procedure Call (RPC) runtime improperly
    initializes objects in memory. An attacker who
    successfully exploited this vulnerability could obtain
    information to further compromise the users system.
    (CVE-2019-1409)

  - An elevation of privilege vulnerability exists in the
    way that the dssvc.dll handles file creation allowing
    for a file overwrite or creation in a secured location.
    An attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2019-1420)

  - An elevation of privilege vulnerability exists in the
    way that the iphlpsvc.dll handles file creation allowing
    for a file overwrite. An attacker who successfully
    exploited the vulnerability could execute code with
    elevated permissions.  (CVE-2019-1422)");
  # https://support.microsoft.com/en-us/help/4525236/windows-10-update-kb4525236
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c647fbe4");
  script_set_attribute(attribute:"solution", value:
"Apply Cumulative Update KB4525236.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1406");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-1384");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft UPnP Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS19-11";
kbs = make_list('4525236');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"14393",
                   rollup_date:"11_2019",
                   bulletin:bulletin,
                   rollup_kb_list:[4525236])
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
