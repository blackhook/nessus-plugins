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
  script_id(138457);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/24");

  script_cve_id(
    "CVE-2020-1085",
    "CVE-2020-1147",
    "CVE-2020-1249",
    "CVE-2020-1267",
    "CVE-2020-1333",
    "CVE-2020-1336",
    "CVE-2020-1344",
    "CVE-2020-1346",
    "CVE-2020-1347",
    "CVE-2020-1351",
    "CVE-2020-1352",
    "CVE-2020-1353",
    "CVE-2020-1354",
    "CVE-2020-1357",
    "CVE-2020-1358",
    "CVE-2020-1359",
    "CVE-2020-1360",
    "CVE-2020-1361",
    "CVE-2020-1362",
    "CVE-2020-1363",
    "CVE-2020-1364",
    "CVE-2020-1365",
    "CVE-2020-1366",
    "CVE-2020-1368",
    "CVE-2020-1369",
    "CVE-2020-1370",
    "CVE-2020-1371",
    "CVE-2020-1372",
    "CVE-2020-1373",
    "CVE-2020-1374",
    "CVE-2020-1375",
    "CVE-2020-1384",
    "CVE-2020-1385",
    "CVE-2020-1386",
    "CVE-2020-1387",
    "CVE-2020-1388",
    "CVE-2020-1389",
    "CVE-2020-1390",
    "CVE-2020-1392",
    "CVE-2020-1393",
    "CVE-2020-1394",
    "CVE-2020-1395",
    "CVE-2020-1396",
    "CVE-2020-1397",
    "CVE-2020-1398",
    "CVE-2020-1399",
    "CVE-2020-1400",
    "CVE-2020-1401",
    "CVE-2020-1402",
    "CVE-2020-1403",
    "CVE-2020-1404",
    "CVE-2020-1406",
    "CVE-2020-1407",
    "CVE-2020-1408",
    "CVE-2020-1409",
    "CVE-2020-1410",
    "CVE-2020-1411",
    "CVE-2020-1412",
    "CVE-2020-1413",
    "CVE-2020-1418",
    "CVE-2020-1419",
    "CVE-2020-1420",
    "CVE-2020-1421",
    "CVE-2020-1427",
    "CVE-2020-1428",
    "CVE-2020-1429",
    "CVE-2020-1430",
    "CVE-2020-1432",
    "CVE-2020-1433",
    "CVE-2020-1434",
    "CVE-2020-1435",
    "CVE-2020-1436",
    "CVE-2020-1437",
    "CVE-2020-1438",
    "CVE-2020-1462",
    "CVE-2020-1463",
    "CVE-2020-1468"
  );
  script_xref(name:"MSKB", value:"4565508");
  script_xref(name:"MSFT", value:"MS20-4565508");
  script_xref(name:"IAVA", value:"2020-A-0300-S");
  script_xref(name:"IAVA", value:"2020-A-0302-S");
  script_xref(name:"IAVA", value:"2020-A-0313-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"KB4565508: Windows 10 Version 1709 July 2020 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4565508. It is, 
therefore, affected by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists when the
    Windows System Events Broker improperly handles file
    operations. An attacker who successfully exploited this
    vulnerability could gain elevated privileges.
    (CVE-2020-1357)

  - An elevation of privilege vulnerability exists when the
    Windows kernel fails to properly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could run arbitrary code in kernel mode.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights.  (CVE-2020-1411)

  - An elevation of privilege vulnerability exists when the
    Windows Diagnostics Execution Service fails to properly
    sanitize input, leading to an unsecure library-loading
    behavior. An attacker who successfully exploited this
    vulnerability could run arbitrary code with elevated
    system privileges. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2020-1418)

  - An elevation of privilege vulnerability exists when the
    Windows USO Core Worker improperly handles memory.
    (CVE-2020-1352)

  - An elevation of privilege vulnerability exists when
    Windows improperly handles COM object creation. An
    attacker who successfully exploited the vulnerability
    could run arbitrary code with elevated privileges.
    (CVE-2020-1375)

  - A remote code execution vulnerability exists in the way
    that DirectWrite handles objects in memory. An attacker
    who successfully exploited this vulnerability could take
    control of the affected system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights. There are
    multiple ways an attacker could exploit the
    vulnerability, such as by convincing a user to open a
    specially crafted document, or by convincing a user to
    visit an untrusted webpage. The security update
    addresses the vulnerability by correcting how
    DirectWrite handles objects in memory. (CVE-2020-1409)

  - An elevation of privilege vulnerability exists when the
    Windows Profile Service improperly handles file
    operations. An attacker who successfully exploited this
    vulnerability could gain elevated privileges.
    (CVE-2020-1360)

  - An elevation of privilege vulnerability exists when
    Windows Mobile Device Management (MDM) Diagnostics
    improperly handles objects in memory. An attacker who
    successfully exploited this vulnerability could bypass
    access restrictions to delete files.  (CVE-2020-1372)

  - An elevation of privilege vulnerability exists when the
    Windows Picker Platform improperly handles memory.
    (CVE-2020-1363)

  - An elevation of privilege vulnerability exists when
    Windows improperly handles calls to Advanced Local
    Procedure Call (ALPC). An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    the security context of the local system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2020-1396)

  - A remote code execution vulnerability exists in the way
    that the VBScript engine handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2020-1403)

  - A remote code execution vulnerability exists in the
    Windows Remote Desktop Client when a user connects to a
    malicious server. An attacker who successfully exploited
    this vulnerability could execute arbitrary code on the
    computer of the connecting client. An attacker could
    then install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2020-1374)

  - A remote code execution vulnerability exists when the
    Windows font library improperly handles specially
    crafted fonts. For all systems except Windows 10, an
    attacker who successfully exploited the vulnerability
    could execute code remotely. For systems running Windows
    10, an attacker who successfully exploited the
    vulnerability could execute code in an AppContainer
    sandbox context with limited privileges and
    capabilities. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights. There are multiple ways an
    attacker could exploit the vulnerability:
    (CVE-2020-1436)

  - An elevation of privilege vulnerability exists in the
    way that the Credential Enrollment Manager service
    handles objects in memory. An attacker who successfully
    exploited the vulnerability could execute code with
    elevated permissions.  (CVE-2020-1368)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Network List Service handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could execute code with
    elevated permissions.  (CVE-2020-1406)

  - An information disclosure vulnerability exists when the
    Windows Graphics component improperly handles objects in
    memory. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system. An authenticated attacker
    could exploit this vulnerability by running a specially
    crafted application. The update addresses the
    vulnerability by correcting how the Windows Graphics
    Component handles objects in memory. (CVE-2020-1351)

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
    in memory. (CVE-2020-1468)

  - An elevation of privilege vulnerability exists when the
    Windows Event Logging Service improperly handles memory.
    (CVE-2020-1365, CVE-2020-1371)

  - An information disclosure vulnerability exists when the
    Windows kernel fails to properly initialize a memory
    address. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2020-1389,
    CVE-2020-1419)

  - An elevation of privilege vulnerability exists when the
    Windows Print Workflow Service improperly handles
    objects in memory. An attacker who successfully
    exploited this vulnerability could gain elevated
    privileges and break out of the AppContainer sandbox.
    (CVE-2020-1366)

  - An elevation of privilege vulnerability exists in the
    way that the Windows WalletService handles objects in
    memory. An attacker who successfully exploited the
    vulnerability could execute code with elevated
    permissions.  (CVE-2020-1344, CVE-2020-1362,
    CVE-2020-1369)

  - An elevation of privilege vulnerability exists when the
    Windows ActiveX Installer Service improperly handles
    memory.  (CVE-2020-1402)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Geolocation Framework handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could execute code with
    elevated permissions.  (CVE-2020-1394)

  - An information vulnerability exists when Windows
    Connected User Experiences and Telemetry Service
    improperly discloses file information. Successful
    exploitation of the vulnerability could allow the
    attacker to read any file on the file system.
    (CVE-2020-1386)

  - This security update corrects a denial of service in the
    Local Security Authority Subsystem Service (LSASS)
    caused when an authenticated attacker sends a specially
    crafted authentication request. A remote attacker who
    successfully exploited this vulnerability could cause a
    denial of service on the target system's LSASS service,
    which triggers an automatic reboot of the system. The
    security update addresses the vulnerability by changing
    the way that LSASS handles specially crafted
    authentication requests. (CVE-2020-1267)

  - An elevation of privilege vulnerability exists when the
    Windows Delivery Optimization service improperly handles
    objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code
    with elevated system privileges. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2020-1392)

  - A remote code execution vulnerability exists when
    Windows Address Book (WAB) improperly processes vcard
    files.  (CVE-2020-1410)

  - An elevation of privilege vulnerability exists when the
    Windows Modules Installer improperly handles file
    operations. An attacker who successfully exploited this
    vulnerability could gain elevated privileges.
    (CVE-2020-1346)

  - An elevation of privilege vulnerability exists when the
    Windows UPnP Device Host improperly handles memory.
    (CVE-2020-1354, CVE-2020-1430)

  - An elevation of privilege vulnerability exists in the
    way that the SharedStream Library handles objects in
    memory. An attacker who successfully exploited the
    vulnerability could execute code with elevated
    permissions.  (CVE-2020-1463)

  - An elevation of privilege vulnerability exists when
    Group Policy Services Policy Processing improperly
    handle reparse points. An attacker who successfully
    exploited this vulnerability could overwrite a targeted
    file that would normally require elevated permissions.
    (CVE-2020-1333)

  - An elevation of privilege vulnerability exists in the
    way the Windows Push Notification Service handles
    objects in memory. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context. An attacker could then install
    programs; view, change or delete data.  (CVE-2020-1387)

  - A remote code execution vulnerability exists when the
    Windows font library improperly handles specially
    crafted embedded fonts. An attacker who successfully
    exploited the vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2020-1408)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Kernel handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2020-1336)

  - An elevation of privilege vulnerability exists when the
    Windows Storage Services improperly handle file
    operations. An attacker who successfully exploited this
    vulnerability could gain elevated privileges.
    (CVE-2020-1347)

  - A denial of service vulnerability exists in the way that
    the WalletService handles files. An attacker who
    successfully exploited the vulnerability could corrupt
    system files.  (CVE-2020-1364)

  - An information disclosure vulnerability exists when
    Skype for Business is accessed via Internet Explorer. An
    attacker who exploited the vulnerability could cause the
    user to place a call without additional consent, leading
    to information disclosure of the user profile. For the
    vulnerability to be exploited, a user must click a
    specially crafted URL that prompts the Skype app.
    (CVE-2020-1432)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Network Location Awareness Service
    handles objects in memory. An attacker who successfully
    exploited the vulnerability could allow an application
    with limited privileges on an affected system to execute
    code at a medium integrity level.  (CVE-2020-1437)

  - An elevation of privilege vulnerability exists when the
    Windows Diagnostics Hub Standard Collector Service fails
    to properly sanitize input, leading to an unsecure
    library-loading behavior. An attacker who successfully
    exploited this vulnerability could run arbitrary code
    with elevated system privileges. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2020-1393)

  - A remote code execution vulnerability exists in .NET
    Framework, Microsoft SharePoint, and Visual Studio when
    the software fails to check the source markup of XML
    file input. An attacker who successfully exploited the
    vulnerability could run arbitrary code in the context of
    the process responsible for deserialization of the XML
    content.  (CVE-2020-1147)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Network Connections Service handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could execute code with
    elevated permissions.  (CVE-2020-1373, CVE-2020-1390,
    CVE-2020-1427, CVE-2020-1428, CVE-2020-1438)

  - An elevation of privilege vulnerability exists when the
    Windows Cryptography Next Generation (CNG) Key Isolation
    service improperly handles memory. An attacker who
    successfully exploited this vulnerability could run
    processes in an elevated context.  (CVE-2020-1359,
    CVE-2020-1384)

  - An information disclosure vulnerability exists when the
    Windows Resource Policy component improperly handles
    memory.  (CVE-2020-1358)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Speech Brokered API handles objects
    in memory. An attacker who successfully exploited the
    vulnerability could execute code with elevated
    permissions.  (CVE-2020-1395)

  - An information disclosure vulnerability exists when
    Windows Error Reporting improperly handles file
    operations.  (CVE-2020-1420)

  - A remote code execution vulnerability exists in the way
    that Microsoft Graphics Components handle objects in
    memory. An attacker who successfully exploited the
    vulnerability could execute arbitrary code on a target
    system.  (CVE-2020-1412)

  - An elevation of privilege vulnerability exists when the
    Windows Runtime improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could run arbitrary code in an elevated context. An
    attacker could exploit this vulnerability by running a
    specially crafted application on the victim system. The
    update addresses the vulnerability by correcting the way
    the Windows Runtime handles objects in memory.
    (CVE-2020-1249, CVE-2020-1353, CVE-2020-1370,
    CVE-2020-1399, CVE-2020-1404, CVE-2020-1413)

  - An information disclosure vulnerability exists when
    Microsoft Edge PDF Reader improperly handles objects in
    memory. An attacker who successfully exploited the
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2020-1433)

  - A remote code execution vulnerability exists when the
    Windows Jet Database Engine improperly handles objects
    in memory. An attacker who successfully exploited this
    vulnerability could execute arbitrary code on a victim
    system. An attacker could exploit this vulnerability by
    enticing a victim to open a specially crafted file. The
    update addresses the vulnerability by correcting the way
    the Windows Jet Database Engine handles objects in
    memory. (CVE-2020-1400, CVE-2020-1401, CVE-2020-1407)

  - An elevation of privilege vulnerability exists when
    Windows Error Reporting manager improperly handles a
    process crash. An attacker who successfully exploited
    this vulnerability could delete a targeted file leading
    to an elevated status.  (CVE-2020-1429)

  - An elevation of privilege vulnerability exists in the
    way that the psmsrv.dll handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2020-1388)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Credential Picker handles objects
    in memory. An attacker who successfully exploited the
    vulnerability could allow an application with limited
    privileges on an affected system to execute code at a
    medium integrity level.  (CVE-2020-1385)

  - A remote code execution vulnerability exists in
    Microsoft Windows that could allow remote code execution
    if a .LNK file is processed. An attacker who
    successfully exploited this vulnerability could gain the
    same user rights as the local user.  (CVE-2020-1421)

  - An information disclosure vulnerability exists in
    Windows when the Windows Imaging Component fails to
    properly handle objects in memory. An attacker who
    successfully exploited this vulnerability could obtain
    information to further compromise the user's system.
    There are multiple ways an attacker could exploit this
    vulnerability:  (CVE-2020-1397)

  - A remote code execution vulnerability exists in the way
    that the Windows Graphics Device Interface (GDI) handles
    objects in the memory. An attacker who successfully
    exploited this vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2020-1435)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Function Discovery Service handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could execute code with
    elevated permissions.  (CVE-2020-1085)

  - An information disclosure vulnerability exists in the
    way that the WalletService handles memory.
    (CVE-2020-1361)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Sync Host Service handles objects
    in memory. An attacker who successfully exploited the
    vulnerability could allow an application with limited
    privileges on an affected system to execute code at a
    medium integrity level.  (CVE-2020-1434)

  - An information disclosure vulnerability exists when
    Skype for Business is accessed via Microsoft Edge
    (EdgeHTML-based). An attacker who exploited the
    vulnerability could cause the user to place a call
    without additional consent, leading to information
    disclosure of the user profile. For the vulnerability to
    be exploited, a user must click a specially crafted URL
    that prompts the Skype app.  (CVE-2020-1462)

  - An elevation of privilege vulnerability exists when
    Windows Lockscreen fails to properly handle Ease of
    Access dialog. An attacker who successfully exploited
    the vulnerability could execute commands with elevated
    permissions. The security update addresses the
    vulnerability by ensuring that the Ease of Access dialog
    is handled properly. (CVE-2020-1398)");
  # https://support.microsoft.com/en-us/help/4565508/windows-10-update-kb4565508
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2aadf5b");
  script_set_attribute(attribute:"solution", value:
"Apply Cumulative Update KB4565508.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1435");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-1436");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SharePoint DataSet / DataTable Deserialization');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/14");

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

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS20-07';
kbs = make_list(
  '4565508'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'10',
                   sp:0,
                   os_build:'16299',
                   rollup_date:'07_2020',
                   bulletin:bulletin,
                   rollup_kb_list:[4565508])
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


