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
  script_id(136506);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/27");

  script_cve_id(
    "CVE-2020-0909",
    "CVE-2020-0963",
    "CVE-2020-1010",
    "CVE-2020-1021",
    "CVE-2020-1035",
    "CVE-2020-1037",
    "CVE-2020-1048",
    "CVE-2020-1051",
    "CVE-2020-1054",
    "CVE-2020-1058",
    "CVE-2020-1060",
    "CVE-2020-1061",
    "CVE-2020-1062",
    "CVE-2020-1064",
    "CVE-2020-1067",
    "CVE-2020-1068",
    "CVE-2020-1070",
    "CVE-2020-1071",
    "CVE-2020-1072",
    "CVE-2020-1076",
    "CVE-2020-1078",
    "CVE-2020-1079",
    "CVE-2020-1081",
    "CVE-2020-1082",
    "CVE-2020-1084",
    "CVE-2020-1086",
    "CVE-2020-1088",
    "CVE-2020-1092",
    "CVE-2020-1093",
    "CVE-2020-1108",
    "CVE-2020-1112",
    "CVE-2020-1113",
    "CVE-2020-1114",
    "CVE-2020-1116",
    "CVE-2020-1123",
    "CVE-2020-1124",
    "CVE-2020-1125",
    "CVE-2020-1131",
    "CVE-2020-1132",
    "CVE-2020-1134",
    "CVE-2020-1136",
    "CVE-2020-1139",
    "CVE-2020-1141",
    "CVE-2020-1143",
    "CVE-2020-1144",
    "CVE-2020-1149",
    "CVE-2020-1153",
    "CVE-2020-1154",
    "CVE-2020-1156",
    "CVE-2020-1157",
    "CVE-2020-1164",
    "CVE-2020-1174",
    "CVE-2020-1175",
    "CVE-2020-1176",
    "CVE-2020-1179"
  );
  script_xref(name:"MSKB", value:"4556826");
  script_xref(name:"MSFT", value:"MS20-4556826");
  script_xref(name:"IAVA", value:"2020-A-0201-S");
  script_xref(name:"IAVA", value:"2020-A-0214-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"KB4556826: Windows 10 May 2020 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4556826.
It is, therefore, affected by multiple vulnerabilities :

  - A denial of service vulnerability exists when .NET Core
    or .NET Framework improperly handles web requests. An
    attacker who successfully exploited this vulnerability
    could cause a denial of service against a .NET Core or
    .NET Framework web application. The vulnerability can be
    exploited remotely, without authentication. A remote
    unauthenticated attacker could exploit this
    vulnerability by issuing specially crafted requests to
    the .NET Core or .NET Framework application. The update
    addresses the vulnerability by correcting how the .NET
    Core or .NET Framework web application handles web
    requests. (CVE-2020-1108)

  - An information disclosure vulnerability exists in the
    way that the Windows Graphics Device Interface (GDI)
    handles objects in memory, allowing an attacker to
    retrieve information from a targeted system. By itself,
    the information disclosure does not allow arbitrary code
    execution; however, it could allow arbitrary code to be
    run if the attacker uses it in combination with another
    vulnerability.  (CVE-2020-1141)

  - An elevation of privilege vulnerability exists in
    Windows Error Reporting (WER) when WER handles and
    executes files. The vulnerability could allow elevation
    of privilege if an attacker can successfully exploit it.
    An attacker who successfully exploited the vulnerability
    could gain greater access to sensitive information and
    system functionality.  (CVE-2020-1021, CVE-2020-1082,
    CVE-2020-1088)

  - A denial of service vulnerability exists when Hyper-V on
    a Windows Server fails to properly handle specially
    crafted network packets.  (CVE-2020-0909)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2020-1072)

  - A denial of service vulnerability exists when Connected
    User Experiences and Telemetry Service improperly
    handles file operations. An attacker who successfully
    exploited this vulnerability could cause a system to
    stop responding.  (CVE-2020-1123)

  - A Denial Of Service vulnerability exists when Connected
    User Experiences and Telemetry Service fails to validate
    certain function values. An attacker who successfully
    exploited this vulnerability could deny dependent
    security feature functionality.  (CVE-2020-1084)

  - An elevation of privilege vulnerability exists when the
    Windows Print Spooler service improperly allows
    arbitrary writing to the file system. An attacker who
    successfully exploited this vulnerability could run
    arbitrary code with elevated system privileges. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts with full user
    rights.  (CVE-2020-1048, CVE-2020-1070)

  - A denial of service vulnerability exists when Windows
    improperly handles objects in memory. An attacker who
    successfully exploited the vulnerability could cause a
    target system to stop responding.  (CVE-2020-1076)

  - A remote code execution vulnerability exists when the
    Windows Jet Database Engine improperly handles objects
    in memory. An attacker who successfully exploited this
    vulnerability could execute arbitrary code on a victim
    system. An attacker could exploit this vulnerability by
    enticing a victim to open a specially crafted file. The
    update addresses the vulnerability by correcting the way
    the Windows Jet Database Engine handles objects in
    memory. (CVE-2020-1051, CVE-2020-1174, CVE-2020-1175,
    CVE-2020-1176)

  - An elevation of privilege vulnerability exists when the
    Windows fails to properly handle objects in memory. An
    attacker who successfully exploited this vulnerability
    could run arbitrary code. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2020-1079)

  - An elevation of privilege vulnerability exists when the
    Windows State Repository Service improperly handles
    objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    an elevated context. An attacker could exploit this
    vulnerability by running a specially crafted application
    on the victim system. The update addresses the
    vulnerability by correcting the way the Windows State
    Repository Service handles objects in memory.
    (CVE-2020-1124, CVE-2020-1131, CVE-2020-1134,
    CVE-2020-1144)

  - An elevation of privilege vulnerability exists in
    Windows Block Level Backup Engine Service (wbengine)
    that allows file deletion in arbitrary locations.
    (CVE-2020-1010)

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
    in memory. (CVE-2020-0963, CVE-2020-1179)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2020-1062,
    CVE-2020-1092)

  - An elevation of privilege vulnerability exists in
    Windows Installer because of the way Windows Installer
    handles certain filesystem operations.  (CVE-2020-1078)

  - A remote code execution vulnerability exists in the way
    that the MSHTML engine improperly validates input. An
    attacker could execute arbitrary code in the context of
    the current user.  (CVE-2020-1064)

  - A remote code execution vulnerability exists in the way
    that Microsoft Graphics Components handle objects in
    memory. An attacker who successfully exploited the
    vulnerability could execute arbitrary code on a target
    system.  (CVE-2020-1153)

  - An elevation of privilege vulnerability exists in
    Windows when the Windows kernel-mode driver fails to
    properly handle objects in memory. An attacker who
    successfully exploited this vulnerability could run
    arbitrary code in kernel mode. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2020-1054, CVE-2020-1143)

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
    Foundation handles objects in memory. (CVE-2020-1136)

  - A remote code execution vulnerability exists in the way
    that Windows handles objects in memory. An attacker who
    successfully exploited the vulnerability could execute
    arbitrary code with elevated permissions on a target
    system.  (CVE-2020-1067)

  - An elevation of privilege vulnerability exists when
    Windows Error Reporting manager improperly handles file
    and folder links. An attacker who successfully exploited
    this vulnerability could overwrite a targeted file
    leading to an elevated status.  (CVE-2020-1132)

  - A security feature bypass vulnerability exists in
    Microsoft Windows when the Task Scheduler service fails
    to properly verify client connections over RPC. An
    attacker who successfully exploited this vulnerability
    could run arbitrary code as an administrator. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts with full user
    rights.  (CVE-2020-1113)

  - An elevation of privilege vulnerability exists when the
    Windows Background Intelligent Transfer Service (BITS)
    IIS module improperly handles uploaded content. An
    attacker who successfully exploited this vulnerability
    could upload restricted file types to an IIS-hosted
    folder.  (CVE-2020-1112)

  - An elevation of privilege vulnerability exists when the
    Windows Printer Service improperly validates file paths
    while loading printer drivers. An authenticated attacker
    who successfully exploited this vulnerability could run
    arbitrary code with elevated system privileges.
    (CVE-2020-1081)

  - A remote code execution vulnerability exists in the way
    that the Microsoft Script Runtime handles objects in
    memory. The vulnerability could corrupt memory in such a
    way that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2020-1061)

  - An elevation of privilege vulnerability exists when
    Windows improperly handles errors tied to Remote Access
    Common Dialog. An attacker who successfully exploited
    the vulnerability could run arbitrary code with elevated
    privileges.  (CVE-2020-1071)

  - A remote code execution vulnerability exists in the way
    that the Chakra scripting engine handles objects in
    memory in Microsoft Edge (HTML-based). The vulnerability
    could corrupt memory in such a way that an attacker
    could execute arbitrary code in the context of the
    current user. An attacker who successfully exploited the
    vulnerability could gain the same user rights as the
    current user.  (CVE-2020-1037)

  - An elevation of privilege vulnerability exists when the
    Windows kernel fails to properly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could run arbitrary code in kernel mode.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights.  (CVE-2020-1114)

  - An elevation of privilege vulnerability exists when the
    Windows Common Log File System (CLFS) driver improperly
    handles objects in memory. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context.  (CVE-2020-1154)

  - An elevation of privilege vulnerability exists in
    Windows Media Service that allows file creation in
    arbitrary locations.  (CVE-2020-1068)

  - An elevation of privilege vulnerability exists when the
    Windows Runtime improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could run arbitrary code in an elevated context. An
    attacker could exploit this vulnerability by running a
    specially crafted application on the victim system. The
    update addresses the vulnerability by correcting the way
    the Windows Runtime handles objects in memory.
    (CVE-2020-1086, CVE-2020-1125, CVE-2020-1139,
    CVE-2020-1149, CVE-2020-1156, CVE-2020-1157,
    CVE-2020-1164)

  - An information disclosure vulnerability exists when the
    Windows Client Server Run-Time Subsystem (CSRSS) fails
    to properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could obtain
    information to further compromise the users system.
    (CVE-2020-1116)

  - A remote code execution vulnerability exists in the way
    that the VBScript engine handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2020-1035, CVE-2020-1058,
    CVE-2020-1060, CVE-2020-1093)");
  # https://support.microsoft.com/en-us/help/4556826/windows-10-update-kb4556826
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22034bc1");
  script_set_attribute(attribute:"solution", value:
"Apply Cumulative Update KB4556826.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1176");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-1112");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Spooler Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/12");

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

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS20-05';
kbs = make_list(
  '4556826'
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
                   os_build:'10240',
                   rollup_date:'05_2020',
                   bulletin:bulletin,
                   rollup_kb_list:[4556826])
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


