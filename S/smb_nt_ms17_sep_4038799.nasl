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
  script_id(103132);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2017-0161",
    "CVE-2017-8529",
    "CVE-2017-8675",
    "CVE-2017-8676",
    "CVE-2017-8677",
    "CVE-2017-8678",
    "CVE-2017-8679",
    "CVE-2017-8680",
    "CVE-2017-8681",
    "CVE-2017-8682",
    "CVE-2017-8683",
    "CVE-2017-8684",
    "CVE-2017-8686",
    "CVE-2017-8687",
    "CVE-2017-8688",
    "CVE-2017-8692",
    "CVE-2017-8695",
    "CVE-2017-8699",
    "CVE-2017-8708",
    "CVE-2017-8709",
    "CVE-2017-8713",
    "CVE-2017-8714",
    "CVE-2017-8719",
    "CVE-2017-8720",
    "CVE-2017-8728",
    "CVE-2017-8733",
    "CVE-2017-8737",
    "CVE-2017-8741",
    "CVE-2017-8747",
    "CVE-2017-8749",
    "CVE-2017-8759"
  );
  script_xref(name:"MSKB", value:"4038786");
  script_xref(name:"MSKB", value:"4038799");
  script_xref(name:"MSFT", value:"MS17-4038786");
  script_xref(name:"MSFT", value:"MS17-4038799");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Windows Server 2012 September 2017 Security Updates");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4038786
or cumulative update 4038799. It is, therefore, affected by
multiple vulnerabilities :

  - A race condition that could lead to a remote code
    execution vulnerability exists in NetBT Session Services
    when NetBT fails to maintain certain sequencing
    requirements. (CVE-2017-0161)

  - An elevation of privilege vulnerability exists in
    Windows when the Windows kernel-mode driver fails to
    properly handle objects in memory. An attacker who
    successfully exploited this vulnerability could run
    arbitrary code in kernel mode. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2017-8675)

  - An information disclosure vulnerability exists in the
    way that the Windows Graphics Device Interface (GDI)
    handles objects in memory, allowing an attacker to
    retrieve information from a targeted system. By itself,
    the information disclosure does not allow arbitrary code
    execution; however, it could allow arbitrary code to be
    run if the attacker uses it in combination with another
    vulnerability. (CVE-2017-8676)

  - A remote code execution vulnerability exists when the
    Windows font library improperly handles specially
    crafted embedded fonts. An attacker who successfully
    exploited this vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights. (CVE-2017-8682)

  - An information disclosure vulnerability exists when the
    Microsoft Windows Graphics Component improperly handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could obtain information to
    further compromise the users system. (CVE-2017-8683)

  - A information disclosure vulnerability exists when the
    Windows GDI+ component improperly discloses kernel
    memory addresses. An attacker who successfully exploited
    the vulnerability could obtain information to further
    compromise the users system. 
    (CVE-2017-8677, CVE-2017-8680, CVE-2017-8681,
    CVE-2017-8684)

  - A memory corruption vulnerability exists in the Windows
    Server DHCP service when an attacker sends specially
    crafted packets to a DHCP failover server. An attacker
    who successfully exploited the vulnerability could
    either run arbitrary code on the DHCP failover server or
    cause the DHCP service to become nonresponsive. To
    exploit the vulnerability, an attacker could send a
    specially crafted packet to a DHCP server. However, the
    DHCP server must be set to failover mode for the attack
    to succeed. The security update addresses the
    vulnerability by correcting how DHCP failover servers
    handle network packets. (CVE-2017-8686)

  - An Information disclosure vulnerability exists in
    Windows kernel that could allow an attacker to retrieve
    information that could lead to a Kernel Address Space
    Layout Randomization (KASLR) bypass. An attacker who
    successfully exploited this vulnerability could retrieve
    the memory address of a kernel object. (CVE-2017-8687)

  - An information disclosure vulnerability exists in the
    way that the Windows Graphics Device Interface+ (GDI+)
    handles objects in memory, allowing an attacker to
    retrieve information from a targeted system. By itself,
    the information disclosure does not allow arbitrary code
    execution; however, it could allow arbitrary code to be
    run if the attacker uses it in combination with another
    vulnerability. (CVE-2017-8688)

  - A remote code execution vulnerability exists due to the
    way Windows Uniscribe handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could take control of the affected system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2017-8692)

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

  - A remote code execution vulnerability exists when
    Windows Shell does not properly validate file copy
    destinations. An attacker who successfully exploited the
    vulnerability could run arbitrary code in the context of
    the current user.
    (CVE-2017-8699)

  - An information disclosure vulnerability exists when the
    Windows kernel fails to properly initialize a memory
    address, allowing an attacker to retrieve information
    that could lead to a Kernel Address Space Layout
    Randomization (KASLR) bypass. An attacker who
    successfully exploited this vulnerability could retrieve
    the base address of the kernel driver from a compromised
    process. (CVE-2017-8708)

  - An information disclosure vulnerability exists when
    Windows Hyper-V on a host operating system fails to
    properly validate input from an authenticated user on a
    guest operating system. (CVE-2017-8713)

  - A remote code execution vulnerability exists in the VM
    Host Agent Service of Remote Desktop Virtual Host role
    when it fails to properly validate input from an
    authenticated user on a guest operating system. To
    exploit the vulnerability, an attacker could issue a
    specially crafted certificate on the guest operating
    system that could cause the VM host agent service on the
    host operating system to execute arbitrary code. The
    Remote Desktop Virtual Host role is not enabled by
    default. An attacker who successfully exploited the
    vulnerability could execute arbitrary code on the host
    operating system. The security update addresses the
    vulnerability by correcting how VM host agent service
    validates guest operating system user input.
    (CVE-2017-8714)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system. (CVE-2017-8678, CVE-2017-8679, CVE-2017-8709,
    CVE-2017-8719)

  - An elevation of privilege vulnerability exists in
    Windows when the Win32k component fails to properly
    handle objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights. (CVE-2017-8720)

  - A spoofing vulnerability exists when Internet Explorer
    improperly handles specific HTML content. An attacker
    who successfully exploited this vulnerability could
    trick a user into believing that the user was visiting a
    legitimate website. The specially crafted website could
    either spoof content or serve as a pivot to chain an
    attack with other vulnerabilities in web services. To
    exploit the vulnerability, the user must either browse
    to a malicious website or be redirected to it. In an
    email attack scenario, an attacker could send an email
    message in an attempt to convince the user to click a
    link to the malicious website. (CVE-2017-8733)

  - A remote code execution vulnerability exists when
    Microsoft Windows PDF Library improperly handles objects
    in memory. The vulnerability could corrupt memory in a
    way that enables an attacker to execute arbitrary code
    in the context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user. 
    (CVE-2017-8728, CVE-2017-8737)

  - A remote code execution vulnerability exists in the way
    that Microsoft browser JavaScript engines render content
    when handling objects in memory. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. (CVE-2017-8741)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. (CVE-2017-8747)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. (CVE-2017-8747,
    CVE-2017-8749)

  - A remote code execution vulnerability exists when
    Microsoft .NET Framework processes untrusted input. An
    attacker who successfully exploited this vulnerability
    in software using the .NET framework could take control
    of an affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights. (CVE-2017-8759)
    
  - An information disclosure vulnerability exists in
    Microsoft browsers in the scripting engines due to
    improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a specially crafted website,
    to disclose files on a user's computer. (CVE-2017-8529)");
  # https://support.microsoft.com/en-us/help/4038786/windows-server-2012-update-kb4038786
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91b2bd74");
  # https://support.microsoft.com/en-us/help/4038799/windows-server-2012-update-kb4038799
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35364720");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB4038786 or Cumulative update KB4038799.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8759");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-8686");

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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS17-09";
kbs = make_list('4038786', '4038799');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Windows 8 EOL
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"6.2",
                   sp:0,
                   rollup_date:"09_2017",
                   bulletin:bulletin,
                   rollup_kb_list:[4038786, 4038799])
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
