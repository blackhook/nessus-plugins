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
  script_id(135469);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-0687",
    "CVE-2020-0784",
    "CVE-2020-0821",
    "CVE-2020-0889",
    "CVE-2020-0895",
    "CVE-2020-0907",
    "CVE-2020-0936",
    "CVE-2020-0937",
    "CVE-2020-0938",
    "CVE-2020-0945",
    "CVE-2020-0946",
    "CVE-2020-0948",
    "CVE-2020-0949",
    "CVE-2020-0950",
    "CVE-2020-0952",
    "CVE-2020-0953",
    "CVE-2020-0955",
    "CVE-2020-0956",
    "CVE-2020-0958",
    "CVE-2020-0959",
    "CVE-2020-0960",
    "CVE-2020-0962",
    "CVE-2020-0964",
    "CVE-2020-0965",
    "CVE-2020-0966",
    "CVE-2020-0967",
    "CVE-2020-0968",
    "CVE-2020-0969",
    "CVE-2020-0982",
    "CVE-2020-0983",
    "CVE-2020-0985",
    "CVE-2020-0987",
    "CVE-2020-0988",
    "CVE-2020-0992",
    "CVE-2020-0993",
    "CVE-2020-0994",
    "CVE-2020-0995",
    "CVE-2020-0999",
    "CVE-2020-1003",
    "CVE-2020-1004",
    "CVE-2020-1005",
    "CVE-2020-1007",
    "CVE-2020-1008",
    "CVE-2020-1009",
    "CVE-2020-1011",
    "CVE-2020-1014",
    "CVE-2020-1015",
    "CVE-2020-1016",
    "CVE-2020-1020",
    "CVE-2020-1027",
    "CVE-2020-1094"
  );
  script_xref(name:"MSKB", value:"4550930");
  script_xref(name:"MSFT", value:"MS20-4550930");
  script_xref(name:"IAVA", value:"2020-A-0156-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");
  script_xref(name:"CEA-ID", value:"CEA-2020-0031");

  script_name(english:"KB4550930: Windows 10 April 2020 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4550930.
It is, therefore, affected by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists when a
    Windows scheduled task improperly handles file
    redirections. An attacker who successfully exploited
    this vulnerability could delete a targeted file they
    would not have permissions to.  (CVE-2020-0936)

  - An information disclosure vulnerability exists when the
    win32k component improperly provides kernel information.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2020-0962)

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
    Foundation handles objects in memory. (CVE-2020-0948,
    CVE-2020-0949, CVE-2020-0950)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2020-0968)

  - A remote code execution vulnerability exists when the
    Windows Jet Database Engine improperly handles objects
    in memory. An attacker who successfully exploited this
    vulnerability could execute arbitrary code on a victim
    system. An attacker could exploit this vulnerability by
    enticing a victim to open a specially crafted file. The
    update addresses the vulnerability by correcting the way
    the Windows Jet Database Engine handles objects in
    memory. (CVE-2020-0889, CVE-2020-0953, CVE-2020-0959,
    CVE-2020-0960, CVE-2020-0988, CVE-2020-0992,
    CVE-2020-0994, CVE-2020-0995, CVE-2020-0999,
    CVE-2020-1008)

  - A remoted code execution vulnerability exists in the way
    that Microsoft Windows Codecs Library handles objects in
    memory. An attacker who successfully exploited the
    vulnerability could execute arbitrary code. Exploitation
    of the vulnerability requires that a program process a
    specially crafted image file. The update addresses the
    vulnerability by correcting how Microsoft Windows Codecs
    Library handles objects in memory. (CVE-2020-0965)

  - An information disclosure vulnerability exists when
    Media Foundation improperly handles objects in memory.
    An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2020-0937,
    CVE-2020-0945, CVE-2020-0946)

  - An elevation of privilege vulnerability exists in the
    way that the Microsoft Store Install Service handles
    file operations in protected locations. An attacker who
    successfully exploited the vulnerability could execute
    code with elevated permissions.  (CVE-2020-1009)

  - A remote code execution vulnerability exists in
    Microsoft Windows when the Windows Adobe Type Manager
    Library improperly handles a specially-crafted multi-
    master font - Adobe Type 1 PostScript format. For all
    systems except Windows 10, an attacker who successfully
    exploited the vulnerability could execute code remotely.
    For systems running Windows 10, an attacker who
    successfully exploited the vulnerability could execute
    code in an AppContainer sandbox context with limited
    privileges and capabilities. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights. There are
    multiple ways an attacker could exploit the
    vulnerability, such as convincing a user to open a
    specially crafted document or viewing it in the Windows
    Preview pane. The update addresses the vulnerability by
    correcting how the Windows Adobe Type Manager Library
    handles Type1 fonts. (CVE-2020-0938, CVE-2020-1020)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Kernel handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2020-1027)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2020-0821, CVE-2020-1007)

  - An elevation of privilege vulnerability exists when the
    Windows Work Folder Service improperly handles file
    operations. An attacker who successfully exploited this
    vulnerability could run processes in an elevated
    context. An attacker could exploit this vulnerability by
    running a specially crafted application on the victim
    system. The update addresses the vulnerability by
    correcting the way the Windows Work Folder Service
    handles file operations. (CVE-2020-1094)

  - A remote code execution vulnerability exists in the way
    that the Windows Graphics Device Interface (GDI) handles
    objects in the memory. An attacker who successfully
    exploited this vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2020-0964)

  - An elevation of privilege vulnerability exists when the
    Windows Update Stack fails to properly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could run arbitrary code in kernel mode.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights.  (CVE-2020-0985)

  - An elevation of privilege vulnerability exists when the
    Windows kernel fails to properly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could run arbitrary code in kernel mode.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights.  (CVE-2020-1003)

  - A remote code execution vulnerability exists when the
    Windows font library improperly handles specially
    crafted embedded fonts. An attacker who successfully
    exploited the vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2020-0687)

  - An elevation of privilege vulnerability exists in the
    Microsoft Windows Update Client when it does not
    properly handle privileges. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context. An attacker could then install
    programs; view, change or delete data.  (CVE-2020-1014)

  - A remote code execution vulnerability exists in the way
    that Microsoft Graphics Components handle objects in
    memory. An attacker who successfully exploited the
    vulnerability could execute arbitrary code on a target
    system.  (CVE-2020-0907)

  - An elevation of privilege vulnerability exists when the
    Windows Graphics Component improperly handles objects in
    memory. An attacker who successfully exploited this
    vulnerability could run processes in an elevated
    context.  (CVE-2020-1004)

  - An elevation of privilege vulnerability exists in the
    way that the User-Mode Power Service (UMPS) handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could execute code with
    elevated permissions.  (CVE-2020-1015)

  - An elevation of privilege vulnerability exists when the
    Windows Delivery Optimization service improperly handles
    objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code
    with elevated system privileges. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2020-0983)

  - An elevation of privilege vulnerability exists in
    Windows when the Windows kernel-mode driver fails to
    properly handle objects in memory. An attacker who
    successfully exploited this vulnerability could run
    arbitrary code in kernel mode. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2020-0956, CVE-2020-0958)

  - An information disclosure vulnerability exists when the
    Microsoft Windows Graphics Component improperly handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could obtain information to
    further compromise the users system.  (CVE-2020-0982,
    CVE-2020-0987, CVE-2020-1005)

  - An elevation of privilege vulnerability exists when
    DirectX improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could run arbitrary code in kernel mode. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2020-0784)

  - An information disclosure vulnerability exists when the
    Windows Push Notification Service improperly handles
    objects in memory. An attacker who successfully
    exploited this vulnerability could obtain information to
    further compromise the users system. An authenticated
    attacker could exploit this vulnerability by running a
    specially crafted application. The update addresses the
    vulnerability by correcting how the Windows Push
    Notification Service handles objects in memory.
    (CVE-2020-1016)

  - A remote code execution vulnerability exists in the way
    that the VBScript engine handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2020-0895, CVE-2020-0966,
    CVE-2020-0967)

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
    in memory. (CVE-2020-0952)

  - A denial of service vulnerability exists in Windows DNS
    when it fails to properly handle queries. An attacker
    who successfully exploited this vulnerability could
    cause the DNS service to become nonresponsive.
    (CVE-2020-0993)

  - An information disclosure vulnerability exists when
    certain central processing units (CPU) speculatively
    access memory. An attacker who successfully exploited
    the vulnerability could read privileged data across
    trust boundaries.  (CVE-2020-0955)

  - An elevation of privilege vulnerability exists when the
    Windows System Assessment Tool improperly handles file
    operations. An attacker who successfully exploited this
    vulnerability could run processes in an elevated
    context. An attacker could exploit this vulnerability by
    running a specially crafted application on the victim
    system. The update addresses the vulnerability by
    correcting the way the Windows System Assessment Tool
    handles file operations. (CVE-2020-1011)
    
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
    new accounts with full user rights. (CVE-2020-0969)");
  # https://support.microsoft.com/en-us/help/4550930/windows-10-update-kb4550930
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b9dba94");
  script_set_attribute(attribute:"solution", value:
"Apply Cumulative Update KB4550930.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1008");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-1020");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS20-04";
kbs = make_list('4550930');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"10240",
                   rollup_date:"04_2020",
                   bulletin:bulletin,
                   rollup_kb_list:[4550930])
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

