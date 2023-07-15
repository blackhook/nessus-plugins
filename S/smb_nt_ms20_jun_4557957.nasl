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
  script_id(137304);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/06");

  script_cve_id(
    "CVE-2020-0915",
    "CVE-2020-0916",
    "CVE-2020-0986",
    "CVE-2020-1120",
    "CVE-2020-1160",
    "CVE-2020-1162",
    "CVE-2020-1194",
    "CVE-2020-1196",
    "CVE-2020-1197",
    "CVE-2020-1199",
    "CVE-2020-1201",
    "CVE-2020-1202",
    "CVE-2020-1203",
    "CVE-2020-1204",
    "CVE-2020-1206",
    "CVE-2020-1207",
    "CVE-2020-1208",
    "CVE-2020-1209",
    "CVE-2020-1211",
    "CVE-2020-1212",
    "CVE-2020-1213",
    "CVE-2020-1214",
    "CVE-2020-1215",
    "CVE-2020-1216",
    "CVE-2020-1217",
    "CVE-2020-1219",
    "CVE-2020-1220",
    "CVE-2020-1222",
    "CVE-2020-1230",
    "CVE-2020-1231",
    "CVE-2020-1232",
    "CVE-2020-1233",
    "CVE-2020-1234",
    "CVE-2020-1235",
    "CVE-2020-1236",
    "CVE-2020-1237",
    "CVE-2020-1238",
    "CVE-2020-1239",
    "CVE-2020-1241",
    "CVE-2020-1242",
    "CVE-2020-1244",
    "CVE-2020-1246",
    "CVE-2020-1247",
    "CVE-2020-1248",
    "CVE-2020-1251",
    "CVE-2020-1253",
    "CVE-2020-1254",
    "CVE-2020-1255",
    "CVE-2020-1257",
    "CVE-2020-1258",
    "CVE-2020-1259",
    "CVE-2020-1261",
    "CVE-2020-1262",
    "CVE-2020-1263",
    "CVE-2020-1264",
    "CVE-2020-1266",
    "CVE-2020-1268",
    "CVE-2020-1269",
    "CVE-2020-1270",
    "CVE-2020-1271",
    "CVE-2020-1272",
    "CVE-2020-1273",
    "CVE-2020-1274",
    "CVE-2020-1275",
    "CVE-2020-1276",
    "CVE-2020-1277",
    "CVE-2020-1278",
    "CVE-2020-1279",
    "CVE-2020-1280",
    "CVE-2020-1281",
    "CVE-2020-1282",
    "CVE-2020-1283",
    "CVE-2020-1284",
    "CVE-2020-1286",
    "CVE-2020-1287",
    "CVE-2020-1290",
    "CVE-2020-1291",
    "CVE-2020-1292",
    "CVE-2020-1293",
    "CVE-2020-1294",
    "CVE-2020-1296",
    "CVE-2020-1299",
    "CVE-2020-1300",
    "CVE-2020-1301",
    "CVE-2020-1302",
    "CVE-2020-1304",
    "CVE-2020-1305",
    "CVE-2020-1306",
    "CVE-2020-1307",
    "CVE-2020-1309",
    "CVE-2020-1311",
    "CVE-2020-1312",
    "CVE-2020-1313",
    "CVE-2020-1314",
    "CVE-2020-1315",
    "CVE-2020-1316",
    "CVE-2020-1317",
    "CVE-2020-1324",
    "CVE-2020-1334",
    "CVE-2020-1348"
  );
  script_xref(name:"MSKB", value:"4557957");
  script_xref(name:"MSFT", value:"MS20-4557957");
  script_xref(name:"IAVA", value:"2020-A-0247-S");
  script_xref(name:"IAVA", value:"2020-A-0256-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0051");

  script_name(english:"KB4557957: Windows 10 Version 2004 June 2020 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4557957.
It is, therefore, affected by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists in the
    way that the wlansvc.dll handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2020-1270)

  - An elevation of privilege vulnerability exists when the
    Windows kernel fails to properly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could run arbitrary code in kernel mode.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights.  (CVE-2020-0986, CVE-2020-1246, CVE-2020-1262,
    CVE-2020-1264, CVE-2020-1266, CVE-2020-1269,
    CVE-2020-1273, CVE-2020-1274, CVE-2020-1275,
    CVE-2020-1276, CVE-2020-1307, CVE-2020-1316)

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
    in memory. (CVE-2020-1348)

  - A vulnerability exists in the way the Windows
    Diagnostics &amp; feedback settings app handles objects
    in memory. An attacker who successfully exploited this
    vulnerability could cause additional diagnostic data
    from the affected device to be sent to Microsoft.
    (CVE-2020-1296)

  - A remote code execution vulnerability exists in the way
    that the VBScript engine handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2020-1213, CVE-2020-1214,
    CVE-2020-1215, CVE-2020-1216, CVE-2020-1230)

  - An information disclosure vulnerability exists when the
    win32k component improperly provides kernel information.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2020-1290)

  - A remote code execution vulnerability exists when
    Microsoft Windows OLE fails to properly validate user
    input. An attacker could exploit the vulnerability to
    execute malicious code.  (CVE-2020-1281)

  - An information disclosure vulnerability exists in the
    way Windows Error Reporting (WER) handles objects in
    memory. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2020-1261,
    CVE-2020-1263)

  - An elevation of privilege vulnerability exists when the
    Windows Background Intelligent Transfer Service (BITS)
    IIS module improperly handles uploaded content. An
    attacker who successfully exploited this vulnerability
    could upload restricted file types to an IIS-hosted
    folder.  (CVE-2020-1255)

  - A denial of service vulnerability exists when Connected
    User Experiences and Telemetry Service improperly
    handles file operations. An attacker who successfully
    exploited this vulnerability could cause a system to
    stop responding.  (CVE-2020-1120, CVE-2020-1244)

  - An elevation of privilege vulnerability exists when
    Windows Error Reporting manager improperly handles a
    process crash. An attacker who successfully exploited
    this vulnerability could delete a targeted file leading
    to an elevated status.  (CVE-2020-1197)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Network Connections Service handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could execute code with
    elevated permissions.  (CVE-2020-1291)

  - A memory corruption vulnerability exists when Windows
    Media Foundation improperly handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could install programs; view, change, or delete data; or
    create new accounts with full user rights. There are
    multiple ways an attacker could exploit the
    vulnerability, such as by convincing a user to open a
    specially crafted document, or by convincing a user to
    visit a malicious webpage. The security update addresses
    the vulnerability by correcting how Windows Media
    Foundation handles objects in memory. (CVE-2020-1238,
    CVE-2020-1239)

  - An elevation of privilege vulnerability exists when the
    Windows Feedback Hub improperly handles objects in
    memory. An attacker who successfully exploited this
    vulnerability could run processes in an elevated
    context.  (CVE-2020-1199)

  - An information disclosure vulnerability exists in the
    way that the Microsoft Server Message Block 3.1.1
    (SMBv3) protocol handles certain requests. An attacker
    who successfully exploited the vulnerability could
    obtain information to further compromise the users
    system.  (CVE-2020-1206)

  - An elevation of privilege vulnerability exists when the
    Diagnostics Hub Standard Collector or the Visual Studio
    Standard Collector fail to properly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could run processes in an elevated
    context.  (CVE-2020-1202, CVE-2020-1203)

  - An elevation of privilege vulnerability exists when
    Windows Mobile Device Management (MDM) Diagnostics
    improperly handles junctions. An attacker who
    successfully exploited this vulnerability could bypass
    access restrictions to delete files.  (CVE-2020-1204)

  - An elevation of privilege vulnerability exists in the
    way the Windows Now Playing Session Manager handles
    objects in memory. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context. An attacker could then install
    programs; view, change or delete data.  (CVE-2020-1201)

  - An elevation of privilege vulnerability exists when the
    Windows Backup Service improperly handles file
    operations.  (CVE-2020-1271)

  - A remote code execution vulnerability exists when the
    Windows Jet Database Engine improperly handles objects
    in memory. An attacker who successfully exploited this
    vulnerability could execute arbitrary code on a victim
    system. An attacker could exploit this vulnerability by
    enticing a victim to open a specially crafted file. The
    update addresses the vulnerability by correcting the way
    the Windows Jet Database Engine handles objects in
    memory. (CVE-2020-1208, CVE-2020-1236)

  - An elevation of privilege vulnerability exists in the
    way that the Connected Devices Platform Service handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could execute code with
    elevated permissions.  (CVE-2020-1211)

  - A security feature bypass vulnerability exists when
    Windows Kernel fails to properly sanitize certain
    parameters.  (CVE-2020-1241)

  - An elevation of privilege vulnerability exists when the
    Diagnostics Hub Standard Collector Service improperly
    handles file operations. An attacker who successfully
    exploited this vulnerability could gain elevated
    privileges. An attacker with unprivileged access to a
    vulnerable system could exploit this vulnerability. The
    security update addresses the vulnerability by ensuring
    the Diagnostics Hub Standard Collector Service properly
    handles file operations. (CVE-2020-1257, CVE-2020-1278,
    CVE-2020-1293)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Bluetooth Service handles objects
    in memory. An attacker who successfully exploited the
    vulnerability could execute code with elevated
    permissions.  (CVE-2020-1280)

  - A remote code execution vulnerability exists in the way
    that the Windows Graphics Device Interface (GDI) handles
    objects in the memory. An attacker who successfully
    exploited this vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2020-1248)

  - An elevation of privilege vulnerability exists in the
    Windows Installer when the Windows Installer fails to
    properly sanitize input leading to an insecure library
    loading behavior. A locally authenticated attacker could
    run arbitrary code with elevated system privileges. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts with full user
    rights. The security update addresses the vulnerability
    by correcting the input sanitization error to preclude
    unintended elevation. (CVE-2020-1272)

  - An information disclosure vulnerability exists when the
    Windows Runtime improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could read memory that was freed and might run arbitrary
    code in an elevated context. An attacker could exploit
    this vulnerability by running a specially crafted
    application on the victim system. The update addresses
    the vulnerability by correcting the way the Windows
    Runtime handles objects in memory. (CVE-2020-1217)

  - An information disclosure vulnerability exists when
    Internet Explorer improperly handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2020-1315)

  - An elevation of privilege vulnerability exists in the
    way that the Windows WalletService handles objects in
    memory. An attacker who successfully exploited the
    vulnerability could execute code with elevated
    permissions.  (CVE-2020-1287, CVE-2020-1294)

  - An information disclosure vulnerability exists when a
    Windows service improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2020-1268)

  - An elevation of privilege vulnerability exists when the
    Windows Update Orchestrator Service improperly handles
    file operations. An attacker who successfully exploited
    this vulnerability could run processes in an elevated
    context. An attacker could exploit this vulnerability by
    running a specially crafted application on the victim
    system. The update addresses the vulnerability by
    correcting the way the Windows Update Orchestrator
    Service handles file operations. (CVE-2020-1313)

  - A remote code execution vulnerability exists when
    Microsoft Windows fails to properly handle cabinet
    files.  (CVE-2020-1300)

  - An elevation of privilege (user to user) vulnerability
    exists in Windows Security Health Service when handling
    certain objects in memory.  (CVE-2020-1162,
    CVE-2020-1324)

  - An elevation of privilege vulnerability exists when the
    Windows Runtime improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could run arbitrary code in an elevated context. An
    attacker could exploit this vulnerability by running a
    specially crafted application on the victim system. The
    update addresses the vulnerability by correcting the way
    the Windows Runtime handles objects in memory.
    (CVE-2020-1231, CVE-2020-1233, CVE-2020-1235,
    CVE-2020-1282, CVE-2020-1304, CVE-2020-1306,
    CVE-2020-1334)

  - An elevation of privilege vulnerability exists when the
    Microsoft Store Runtime improperly handles memory.
    (CVE-2020-1222, CVE-2020-1309)

  - A remote code execution vulnerability exists in the way
    that Microsoft browsers access objects in memory. The
    vulnerability could corrupt memory in a way that could
    allow an attacker to execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2020-1219)

  - A denial of service vulnerability exists when Windows
    Registry improperly handles filesystem operations. An
    attacker who successfully exploited the vulnerability
    could cause a denial of service against a system.
    (CVE-2020-1194)

  - A remote code execution vulnerability exists in
    Microsoft Windows that could allow remote code execution
    if a .LNK file is processed. An attacker who
    successfully exploited this vulnerability could gain the
    same user rights as the local user.  (CVE-2020-1299)

  - An information disclosure vulnerability exists when the
    Microsoft Windows Graphics Component improperly handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could obtain information to
    further compromise the users system.  (CVE-2020-1160)

  - An elevation of privilege vulnerability exists when the
    Windows State Repository Service improperly handles
    objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    an elevated context. An attacker could exploit this
    vulnerability by running a specially crafted application
    on the victim system. The update addresses the
    vulnerability by correcting the way the Windows State
    Repository Service handles objects in memory.
    (CVE-2020-1305)

  - A security feature bypass vulnerability exists when
    Windows Host Guardian Service improperly handles hashes
    recorded and logged. An attacker who successfully
    exploited the vulnerability could tamper with the log
    file. In an attack scenario, an attacker can change
    existing event log types to a type the parsers do not
    interpret allowing an attacker to append their own hash
    without triggering an alert. The update addresses the
    vulnerability by correcting how Windows Host Guardian
    Service handles logging of the measured boot hash.
    (CVE-2020-1259)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Network List Service handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could execute code with
    elevated permissions.  (CVE-2020-1209)

  - A remote code execution vulnerability exists in the way
    that the Microsoft Server Message Block 1.0 (SMBv1)
    server handles certain requests. An attacker who
    successfully exploited the vulnerability could gain the
    ability to execute code on the target server.
    (CVE-2020-1301)

  - An elevation of privilege vulnerability exists in
    Windows Installer because of the way Windows Installer
    handles certain filesystem operations.  (CVE-2020-1277,
    CVE-2020-1302, CVE-2020-1312)

  - An information disclosure vulnerability exists in the
    way that Microsoft Edge handles cross-origin requests.
    An attacker who successfully exploited this
    vulnerability could determine the origin of all webpages
    in the affected browser.  (CVE-2020-1242)

  - An elevation of privilege vulnerability exists when an
    OLE Automation component improperly handles memory.
    (CVE-2020-1212)

  - An elevation of privilege vulnerability exists when
    Group Policy improperly checks access. An attacker who
    successfully exploited this vulnerability could run
    processes in an elevated context.  (CVE-2020-1317)

  - An elevation of privilege vulnerability exists when
    Windows Lockscreen fails to properly load spotlight
    images from a secure location. An attacker who
    successfully exploited the vulnerability could execute
    commands with elevated permissions. An authenticated
    attacker could modify a registry value to exploit this
    vulnerability. The security update addresses the
    vulnerability by ensuring that the spotlight images are
    always loaded from a secure location. (CVE-2020-1279)

  - An elevation of privilege vulnerability exists in
    OpenSSH for Windows when it does not properly restrict
    access to configuration settings. An attacker who
    successfully exploited this vulnerability could replace
    the shell with a malicious binary.  (CVE-2020-1292)

  - An elevation of privilege vulnerability exists in the
    way that the printconfig.dll handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2020-1196)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Graphics Device Interface (GDI)
    handles objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2020-0915, CVE-2020-0916)

  - An elevation of privilege vulnerability exists when
    Windows Modules Installer Service improperly handles
    class object members. A locally authenticated attacker
    could run arbitrary code with elevated system
    privileges. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights. The update addresses the
    vulnerability by correcting how Windows handles calls to
    preclude unintended elevation. (CVE-2020-1254)

  - An elevation of privilege vulnerability exists when
    Component Object Model (COM) client uses special case
    IIDs. An attacker who successfully exploited this
    vulnerability could run arbitrary code with elevated
    system privileges. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2020-1311)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Kernel handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2020-1237)

  - A denial of service vulnerability exists in the way that
    the Microsoft Server Message Block 3.1.1 (SMBv3)
    protocol handles certain requests. An authenticated
    attacker who successfully exploited this vulnerability
    against an SMB Server could cause the affected system to
    crash. An unauthenticated attacker could also exploit
    this this vulnerability against an SMB client and cause
    the affected system to crash.  (CVE-2020-1284)

  - A denial of service vulnerability exists when Windows
    improperly handles objects in memory. An attacker who
    successfully exploited the vulnerability could cause a
    target system to stop responding.  (CVE-2020-1283)

  - An elevation of privilege vulnerability exists when
    Windows Error Reporting improperly handles objects in
    memory.  (CVE-2020-1234)

  - A spoofing vulnerability exists when theMicrosoft Edge
    (Chromium-based) in IE Mode improperly handles specific
    redirects. An attacker who successfully exploits the IE
    Mode vulnerability could trick a user into believing
    that the user was on a legitimate website. The specially
    crafted website could either spoof content or serve as a
    pivot to chain an attack with other vulnerabilities in
    web services.  (CVE-2020-1220)

  - An information disclosure vulnerability exists when
    Media Foundation improperly handles objects in memory.
    An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2020-1232)

  - A remote code execution vulnerability exists when the
    Windows Shell does not properly validate file paths. An
    attacker who successfully exploited this vulnerability
    could run arbitrary code in the context of the current
    user. If the current user is logged on as an
    administrator, an attacker could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with elevated privileges. Users whose accounts
    are configured to have fewer privileges on the system
    could be less impacted than users who operate with
    administrative privileges.  (CVE-2020-1286)

  - An elevation of privilege vulnerability exists in
    Windows when the Windows kernel-mode driver fails to
    properly handle objects in memory. An attacker who
    successfully exploited this vulnerability could run
    arbitrary code in kernel mode. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2020-1207, CVE-2020-1247, CVE-2020-1251,
    CVE-2020-1253)

  - An elevation of privilege vulnerability exists in
    Windows Text Service Framework (TSF) when the TSF server
    fails to properly handle messages sent from TSF clients.
    An attacker who successfully exploited this
    vulnerability could run arbitrary code in a privileged
    process. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2020-1314)

  - An elevation of privilege vulnerability exists when
    DirectX improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could run arbitrary code in kernel mode. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2020-1258)");
  # https://support.microsoft.com/en-us/help/4557957/windows-10-update-kb4557957
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4706967");
  script_set_attribute(attribute:"solution", value:
"Apply Cumulative Update KB4557957.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1307");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-1317");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Windows Update Orchestrator unchecked ScheduleWork call');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/10");

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

bulletin = "MS20-06";
kbs = make_list('4557957');

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
                   rollup_date:"06_2020",
                   bulletin:bulletin,
                   rollup_kb_list:[4557957])
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

