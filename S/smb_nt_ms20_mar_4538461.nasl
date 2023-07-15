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
  script_id(134368);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/20");

  script_cve_id(
    "CVE-2020-0645",
    "CVE-2020-0684",
    "CVE-2020-0690",
    "CVE-2020-0763",
    "CVE-2020-0768",
    "CVE-2020-0769",
    "CVE-2020-0770",
    "CVE-2020-0771",
    "CVE-2020-0772",
    "CVE-2020-0773",
    "CVE-2020-0774",
    "CVE-2020-0775",
    "CVE-2020-0776",
    "CVE-2020-0777",
    "CVE-2020-0778",
    "CVE-2020-0779",
    "CVE-2020-0780",
    "CVE-2020-0781",
    "CVE-2020-0783",
    "CVE-2020-0785",
    "CVE-2020-0787",
    "CVE-2020-0788",
    "CVE-2020-0791",
    "CVE-2020-0793",
    "CVE-2020-0797",
    "CVE-2020-0798",
    "CVE-2020-0799",
    "CVE-2020-0800",
    "CVE-2020-0801",
    "CVE-2020-0802",
    "CVE-2020-0803",
    "CVE-2020-0804",
    "CVE-2020-0806",
    "CVE-2020-0807",
    "CVE-2020-0808",
    "CVE-2020-0809",
    "CVE-2020-0810",
    "CVE-2020-0811",
    "CVE-2020-0812",
    "CVE-2020-0813",
    "CVE-2020-0814",
    "CVE-2020-0816",
    "CVE-2020-0819",
    "CVE-2020-0820",
    "CVE-2020-0822",
    "CVE-2020-0823",
    "CVE-2020-0824",
    "CVE-2020-0825",
    "CVE-2020-0826",
    "CVE-2020-0827",
    "CVE-2020-0828",
    "CVE-2020-0829",
    "CVE-2020-0830",
    "CVE-2020-0831",
    "CVE-2020-0832",
    "CVE-2020-0833",
    "CVE-2020-0834",
    "CVE-2020-0840",
    "CVE-2020-0841",
    "CVE-2020-0842",
    "CVE-2020-0843",
    "CVE-2020-0844",
    "CVE-2020-0845",
    "CVE-2020-0847",
    "CVE-2020-0848",
    "CVE-2020-0849",
    "CVE-2020-0853",
    "CVE-2020-0854",
    "CVE-2020-0857",
    "CVE-2020-0858",
    "CVE-2020-0859",
    "CVE-2020-0860",
    "CVE-2020-0861",
    "CVE-2020-0864",
    "CVE-2020-0865",
    "CVE-2020-0866",
    "CVE-2020-0867",
    "CVE-2020-0868",
    "CVE-2020-0869",
    "CVE-2020-0871",
    "CVE-2020-0877",
    "CVE-2020-0879",
    "CVE-2020-0880",
    "CVE-2020-0881",
    "CVE-2020-0882",
    "CVE-2020-0883",
    "CVE-2020-0885",
    "CVE-2020-0887",
    "CVE-2020-0896",
    "CVE-2020-0897"
  );
  script_xref(name:"MSKB", value:"4538461");
  script_xref(name:"MSFT", value:"MS20-4538461");
  script_xref(name:"IAVA", value:"2020-A-0139-S");
  script_xref(name:"IAVA", value:"2020-A-0214-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/28");

  script_name(english:"KB4538461: Windows 10 Version 1809 and Windows Server 2019 March 2020 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4538461.
It is, therefore, affected by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists when the
    Windows Device Setup Manager improperly handles file
    operations. An attacker who successfully exploited this
    vulnerability could run processes in an elevated
    context. An attacker could exploit this vulnerability by
    running a specially crafted application on the victim
    system. The update addresses the vulnerability by
    correcting the way the Windows Device Setup Manager
    handles file operations. (CVE-2020-0819)

  - An elevation of privilege vulnerability exists when the
    Windows Work Folder Service improperly handles file
    operations. An attacker who successfully exploited this
    vulnerability could run processes in an elevated
    context. An attacker could exploit this vulnerability by
    running a specially crafted application on the victim
    system. The update addresses the vulnerability by
    correcting the way the Windows Work Folder Service
    handles file operations. (CVE-2020-0777, CVE-2020-0797,
    CVE-2020-0800, CVE-2020-0864, CVE-2020-0865,
    CVE-2020-0866, CVE-2020-0897)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2020-0824)

  - An elevation of privilege vulnerability exists in
    Windows Installer because of the way Windows Installer
    handles certain filesystem operations.  (CVE-2020-0814,
    CVE-2020-0842, CVE-2020-0843)

  - An information vulnerability exists when Windows Modules
    Installer Service improperly discloses file information.
    Successful exploitation of the vulnerability could allow
    the attacker to read any file on the file system.
    (CVE-2020-0859)

  - An elevation of privilege vulnerability exists when
    Windows Mobile Device Management (MDM) Diagnostics
    improperly handles junctions. An attacker who
    successfully exploited this vulnerability could bypass
    access restrictions to delete files.  (CVE-2020-0854)

  - An elevation of privilege vulnerability exists when the
    Windows Graphics Component improperly handles objects in
    memory. An attacker who successfully exploited this
    vulnerability could run processes in an elevated
    context.  (CVE-2020-0791)

  - An information disclosure vulnerability exists when
    Windows Network Connections Service fails to properly
    handle objects in memory. An attacker who successfully
    exploited the vulnerability could potentially disclose
    memory contents of an elevated process.  (CVE-2020-0871)

  - An elevation of privilege vulnerability exists when the
    &quot;Public Account Pictures&quot; folder improperly
    handles junctions.  (CVE-2020-0858)

  - A tampering vulnerability exists when Microsoft IIS
    Server improperly handles malformed request headers. An
    attacker who successfully exploited the vulnerability
    could cause a vulnerable server to improperly process
    HTTP headers and tamper with the responses returned to
    clients.  (CVE-2020-0645)

  - An elevation of privilege vulnerability exists in the
    way the Provisioning Runtime validates certain file
    operations. An attacker who successfully exploited the
    vulnerability could gain elevated privileges on a victim
    system.  (CVE-2020-0808)

  - An elevation of privilege vulnerability exists in
    Windows when the Win32k component fails to properly
    handle objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2020-0788, CVE-2020-0877,
    CVE-2020-0887)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Network Connections Service handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could execute code with
    elevated permissions.  (CVE-2020-0778, CVE-2020-0802,
    CVE-2020-0803, CVE-2020-0804, CVE-2020-0845)

  - An elevation of privilege vulnerability exists in the
    Windows Installer when the Windows Installer fails to
    properly sanitize input leading to an insecure library
    loading behavior. A locally authenticated attacker could
    run arbitrary code with elevated system privileges. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts with full user
    rights. The security update addresses the vulnerability
    by correcting the input sanitization error to preclude
    unintended elevation. (CVE-2020-0798)

  - An elevation of privilege vulnerability exists in
    Microsoft Windows when the Windows kernel fails to
    properly handle parsing of certain symbolic links. An
    attacker who successfully exploited this vulnerability
    could potentially access privileged registry keys and
    thereby elevate permissions. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2020-0799)

  - An elevation of privilege vulnerability exists when
    Connected User Experiences and Telemetry Service
    improperly handles file operations. An attacker who
    successfully exploited this vulnerability could run
    processes in an elevated context. An attacker could
    exploit this vulnerability by running a specially
    crafted application on the victim system. The security
    update addresses the vulnerability by correcting how the
    Connected User Experiences and Telemetry Service handles
    file operations. (CVE-2020-0844)

  - An elevation of privilege vulnerability exists when the
    Diagnostics Hub Standard Collector or the Visual Studio
    Standard Collector allows file creation in arbitrary
    locations.  (CVE-2020-0810)

  - A remote code execution vulnerability exists in
    Microsoft Windows that could allow remote code execution
    if a .LNK file is processed. An attacker who
    successfully exploited this vulnerability could gain the
    same user rights as the local user.  (CVE-2020-0684)

  - An elevation of privilege vulnerability exists when
    Windows improperly handles hard links. An attacker who
    successfully exploited this vulnerability could
    overwrite a targeted file leading to an elevated status.
    (CVE-2020-0840, CVE-2020-0841, CVE-2020-0849,
    CVE-2020-0896)

  - An elevation of privilege vulnerability exists when the
    Windows CSC Service improperly handles memory.
    (CVE-2020-0769, CVE-2020-0771)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Search Indexer handles objects in
    memory. An attacker who successfully exploited the
    vulnerability could execute code with elevated
    permissions.  (CVE-2020-0857)

  - An elevation of privilege vulnerability exists in
    Windows Error Reporting (WER) when WER handles and
    executes files. The vulnerability could allow elevation
    of privilege if an attacker can successfully exploit it.
    An attacker who successfully exploited the vulnerability
    could gain greater access to sensitive information and
    system functionality.  (CVE-2020-0806)

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
    in memory. (CVE-2020-0774, CVE-2020-0880, CVE-2020-0882)

  - A remote code execution vulnerability exists in the way
    that the Windows Graphics Device Interface (GDI) handles
    objects in the memory. An attacker who successfully
    exploited this vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2020-0881,
    CVE-2020-0883)

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
    (CVE-2020-0885)

  - An information disclosure vulnerability exists when
    Media Foundation improperly handles objects in memory.
    An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system. An attacker who had already
    gained execution on the victim system could exploit this
    vulnerability by running a specially crafted
    application. The update addresses the vulnerability by
    correcting how Media Foundation handles objects in
    memory. (CVE-2020-0820)

  - An elevation of privilege vulnerability exists when the
    Windows Update Orchestrator Service improperly handles
    file operations. An attacker who successfully exploited
    this vulnerability could run processes in an elevated
    context. An attacker could exploit this vulnerability by
    running a specially crafted application on the victim
    system. The update addresses the vulnerability by
    correcting the way the Windows Update Orchestrator
    Service handles file operations. (CVE-2020-0867,
    CVE-2020-0868)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Network List Service handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could execute code with
    elevated permissions.  (CVE-2020-0780)

  - An elevation of privilege vulnerability exists when
    Windows Defender Security Center handles certain objects
    in memory.  (CVE-2020-0763)

  - An elevation of privilege vulnerability exists when
    Windows improperly handles calls to Advanced Local
    Procedure Call (ALPC). An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    the security context of the local system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2020-0834)

  - An elevation of privilege vulnerability exists when the
    Windows User Profile Service (ProfSvc) improperly
    handles symlinks. An attacker who successfully exploited
    this vulnerability could delete files and folders in an
    elevated context.  (CVE-2020-0785)

  - An elevation of privilege vulnerability exists when the
    Windows Universal Plug and Play (UPnP) service
    improperly handles objects in memory. An attacker who
    successfully exploited this vulnerability could run
    arbitrary code with elevated system privileges. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts with full user
    rights.  (CVE-2020-0781, CVE-2020-0783)

  - An information disclosure vulnerability exists in the
    way that the Windows Graphics Device Interface (GDI)
    handles objects in memory, allowing an attacker to
    retrieve information from a targeted system. By itself,
    the information disclosure does not allow arbitrary code
    execution; however, it could allow arbitrary code to be
    run if the attacker uses it in combination with another
    vulnerability.  (CVE-2020-0879)

  - An information disclosure vulnerability exists when the
    Windows Network Driver Interface Specification (NDIS)
    improperly handles memory.  (CVE-2020-0861)

  - An elevation of privilege vulnerability exists when
    DirectX improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could run arbitrary code in kernel mode. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2020-0690)

  - An elevation of privilege vulnerability exists when the
    Windows AppX Deployment Server improperly handles file
    operations.  (CVE-2020-0776)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2020-0832, CVE-2020-0833)

  - A remote code execution vulnerability exists in the way
    the scripting engine handles objects in memory in
    Microsoft browsers. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2020-0768, CVE-2020-0830)

  - An elevation of privilege vulnerability exists in the
    Windows Installer when MSI packages process symbolic
    links. An attacker who successfully exploited this
    vulnerability could bypass access restrictions to add or
    remove files.  (CVE-2020-0779)

  - An elevation of privilege vulnerability exists when the
    Windows Background Intelligent Transfer Service (BITS)
    improperly handles symbolic links. An attacker who
    successfully exploited this vulnerability could
    overwrite a targeted file leading to an elevated status.
    (CVE-2020-0787)

  - A remote code execution vulnerability exists in the way
    that the VBScript engine handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2020-0847)

  - An elevation of privilege vulnerability exists when the
    Diagnostics Hub Standard Collector Service improperly
    handles file operations. An attacker who successfully
    exploited this vulnerability could gain elevated
    privileges. An attacker with unprivileged access to a
    vulnerable system could exploit this vulnerability. The
    security update addresses the vulnerability by ensuring
    the Diagnostics Hub Standard Collector Service properly
    handles file operations. (CVE-2020-0793)

  - An information disclosure vulnerability exists when
    Windows Error Reporting improperly handles file
    operations.  (CVE-2020-0775)

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
    Foundation handles objects in memory. (CVE-2020-0801,
    CVE-2020-0807, CVE-2020-0809, CVE-2020-0869)

  - An information disclosure vulnerability exists in
    Windows when the Windows Imaging Component fails to
    properly handle objects in memory. An attacker who
    succesfully exploited this vulnerability could obtain
    information to further compromise the user's system.
    There are multiple ways an attacker could exploit this
    vulnerability:  (CVE-2020-0853)

  - An elevation of privilege vulnerability exists when the
    Windows Language Pack Installer improperly handles file
    operations. An attacker who successfully exploited this
    vulnerability could run processes in an elevated
    context. An attacker could exploit this vulnerability by
    running a specially crafted application on the victim
    system. The update addresses the vulnerability by
    correcting the way the Windows Language Pack Installer
    handles file operations. (CVE-2020-0822)

  - An elevation of privilege vulnerability exists when the
    Windows ActiveX Installer Service improperly handles
    memory.  (CVE-2020-0770, CVE-2020-0773, CVE-2020-0860)

  - An elevation of privilege vulnerability exists when
    Windows Error Reporting improperly handles memory.
    (CVE-2020-0772)

 - A remote code execution vulnerability exists in the way 
    that the Chakra scripting engine handles objects in 
    memory in Microsoft Edge (HTML-based). The vulnerability
    could corrupt memory in such a way that an attacker could 
    execute arbitrary code in the context of the current user. 
    An attacker who successfully exploited the vulnerability 
    could gain the same user rights as the current user. If 
    the current user is logged on with administrative user 
    rights, an attacker who successfully exploited the 
    vulnerability could take control of an affected system. 
    An attacker could then install programs; view, change, 
    or delete data; or create new accounts with full user 
    rights. (CVE-2020-0811, CVE-2020-0812)

  - An information disclosure vulnerability exists when 
    Chakra improperly discloses the contents of its memory, 
    which could provide an attacker with information to 
    further compromise the user’s computer or data. 
    (CVE-2020-0813)

  - A remote code execution vulnerability exists when 
    Microsoft Edge improperly accesses objects in memory. 
    The vulnerability could corrupt memory in such a way 
    that enables an attacker to execute arbitrary code in 
    the context of the current user. An attacker who 
    successfully exploited the vulnerability could gain 
    the same user rights as the current user. If the current 
    user is logged on with administrative user rights, an 
    attacker could take control of an affected system. An 
    attacker could then install programs; view, change, or 
    delete data; or create new accounts with full user rights.
    (CVE-2020-0816)

  - A remote code execution vulnerability exists in the way 
    that the ChakraCore scripting engine handles objects in 
    memory. The vulnerability could corrupt memory in such a 
    way that an attacker could execute arbitrary code in the 
    context of the current user. An attacker who successfully 
    exploited the vulnerability could gain the same user 
    rights as the current user. If the current user is logged 
    on with administrative user rights, an attacker who 
    successfully exploited the vulnerability could take 
    control of an affected system. An attacker could then 
    install programs; view, change, or delete data; or create 
    new accounts with full user rights. (CVE-2020-08323,
    CVE-2020-0825, CVE-2020-0826, CVE-2020-0827, CVE-2020-0828, 
    CVE-2020-0829,CVE-2020-0831, CVE-2020-0848)");
  # https://support.microsoft.com/en-us/help/4538461/windows-10-update-kb4538461
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87f654b6");
  script_set_attribute(attribute:"solution", value:
"Apply Cumulative Update KB4538461.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0690");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Background Intelligent Transfer Service Arbitrary File Move Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/10");

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

bulletin = "MS20-03";
kbs = make_list('4538461');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"17763",
                   rollup_date:"03_2020",
                   bulletin:bulletin,
                   rollup_kb_list:[4538461])
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
