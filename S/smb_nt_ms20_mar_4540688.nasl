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
  script_id(134865);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/20");

  script_cve_id(
    "CVE-2020-0645",
    "CVE-2020-0684",
    "CVE-2020-0768",
    "CVE-2020-0769",
    "CVE-2020-0770",
    "CVE-2020-0771",
    "CVE-2020-0772",
    "CVE-2020-0773",
    "CVE-2020-0774",
    "CVE-2020-0778",
    "CVE-2020-0779",
    "CVE-2020-0781",
    "CVE-2020-0783",
    "CVE-2020-0785",
    "CVE-2020-0787",
    "CVE-2020-0788",
    "CVE-2020-0791",
    "CVE-2020-0802",
    "CVE-2020-0803",
    "CVE-2020-0804",
    "CVE-2020-0806",
    "CVE-2020-0814",
    "CVE-2020-0822",
    "CVE-2020-0824",
    "CVE-2020-0830",
    "CVE-2020-0832",
    "CVE-2020-0833",
    "CVE-2020-0842",
    "CVE-2020-0843",
    "CVE-2020-0844",
    "CVE-2020-0845",
    "CVE-2020-0847",
    "CVE-2020-0849",
    "CVE-2020-0853",
    "CVE-2020-0860",
    "CVE-2020-0871",
    "CVE-2020-0874",
    "CVE-2020-0877",
    "CVE-2020-0879",
    "CVE-2020-0880",
    "CVE-2020-0881",
    "CVE-2020-0882",
    "CVE-2020-0883",
    "CVE-2020-0885",
    "CVE-2020-0887"
  );
  script_xref(name:"MSKB", value:"4540688");
  script_xref(name:"MSKB", value:"4541500");
  script_xref(name:"MSFT", value:"MS20-4540688");
  script_xref(name:"MSFT", value:"MS20-4541500");
  script_xref(name:"IAVA", value:"2020-A-0139-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/28");

  script_name(english:"KB4541500: Windows 7 and Windows Server 2008 R2 March 2020 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4541500
or cumulative update 4540688. It is, therefore, affected by
multiple vulnerabilities :

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

  - An elevation of privilege vulnerability exists when the
    Windows Background Intelligent Transfer Service (BITS)
    improperly handles symbolic links. An attacker who
    successfully exploited this vulnerability could
    overwrite a targeted file leading to an elevated status.
    (CVE-2020-0787)

  - An information disclosure vulnerability exists when
    Windows Network Connections Service fails to properly
    handle objects in memory. An attacker who successfully
    exploited the vulnerability could potentially disclose
    memory contents of an elevated process.  (CVE-2020-0871)

  - A tampering vulnerability exists when Microsoft IIS
    Server improperly handles malformed request headers. An
    attacker who successfully exploited the vulnerability
    could cause a vulnerable server to improperly process
    HTTP headers and tamper with the responses returned to
    clients.  (CVE-2020-0645)

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

  - A remote code execution vulnerability exists in
    Microsoft Windows that could allow remote code execution
    if a .LNK file is processed. An attacker who
    successfully exploited this vulnerability could gain the
    same user rights as the local user.  (CVE-2020-0684)

  - An elevation of privilege vulnerability exists when the
    Windows User Profile Service (ProfSvc) improperly
    handles symlinks. An attacker who successfully exploited
    this vulnerability could delete files and folders in an
    elevated context.  (CVE-2020-0785)

  - An information disclosure vulnerability exists in the
    way that the Windows Graphics Device Interface (GDI)
    handles objects in memory, allowing an attacker to
    retrieve information from a targeted system. By itself,
    the information disclosure does not allow arbitrary code
    execution; however, it could allow arbitrary code to be
    run if the attacker uses it in combination with another
    vulnerability.  (CVE-2020-0874, CVE-2020-0879)

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

  - An elevation of privilege vulnerability exists when
    Windows Error Reporting improperly handles memory.
    (CVE-2020-0772)

  - An elevation of privilege vulnerability exists when the
    Windows Universal Plug and Play (UPnP) service
    improperly handles objects in memory. An attacker who
    successfully exploited this vulnerability could run
    arbitrary code with elevated system privileges. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts with full user
    rights.  (CVE-2020-0781, CVE-2020-0783)

  - An elevation of privilege vulnerability exists when
    Windows improperly handles hard links. An attacker who
    successfully exploited this vulnerability could
    overwrite a targeted file leading to an elevated status.
    (CVE-2020-0849)

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
    Windows Graphics Component improperly handles objects in
    memory. An attacker who successfully exploited this
    vulnerability could run processes in an elevated
    context.  (CVE-2020-0791)

  - A remote code execution vulnerability exists in the way
    that the VBScript engine handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2020-0847)

  - An elevation of privilege vulnerability exists when the
    Windows CSC Service improperly handles memory.
    (CVE-2020-0769, CVE-2020-0771)

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
    memory.  (CVE-2020-0770, CVE-2020-0773, CVE-2020-0860)");
  # https://support.microsoft.com/en-us/help/4540688/windows-7-update-kb4540688
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?210cd1ec");
  # https://support.microsoft.com/en-us/help/4541500/windows-7-update-kb4541500
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7405b8a");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB4541500 or Cumulative Update KB4540688.

Please Note: These updates are only available through Microsoft's Extended Support Updates program.
This operating system is otherwise unsupported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0883");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Background Intelligent Transfer Service Arbitrary File Move Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
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
kbs = make_list('4540688', '4541500');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win7:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"6.1",
                   sp:1,
                   rollup_date:"03_2020",
                   bulletin:bulletin,
                   rollup_kb_list:[4540688, 4541500])
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

