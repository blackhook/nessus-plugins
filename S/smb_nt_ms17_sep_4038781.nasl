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
  script_id(104385);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2017-0161",
    "CVE-2017-8529",
    "CVE-2017-8628",
    "CVE-2017-8643",
    "CVE-2017-8675",
    "CVE-2017-8676",
    "CVE-2017-8677",
    "CVE-2017-8678",
    "CVE-2017-8679",
    "CVE-2017-8681",
    "CVE-2017-8682",
    "CVE-2017-8683",
    "CVE-2017-8687",
    "CVE-2017-8688",
    "CVE-2017-8692",
    "CVE-2017-8695",
    "CVE-2017-8699",
    "CVE-2017-8702",
    "CVE-2017-8706",
    "CVE-2017-8707",
    "CVE-2017-8708",
    "CVE-2017-8709",
    "CVE-2017-8713",
    "CVE-2017-8719",
    "CVE-2017-8720",
    "CVE-2017-8723",
    "CVE-2017-8728",
    "CVE-2017-8733",
    "CVE-2017-8734",
    "CVE-2017-8735",
    "CVE-2017-8736",
    "CVE-2017-8737",
    "CVE-2017-8738",
    "CVE-2017-8741",
    "CVE-2017-8747",
    "CVE-2017-8748",
    "CVE-2017-8749",
    "CVE-2017-8750",
    "CVE-2017-8753",
    "CVE-2017-8754",
    "CVE-2017-8756",
    "CVE-2017-8757",
    "CVE-2017-8759",
    "CVE-2017-11766"
  );
  script_bugtraq_id(
    98953,
    100718,
    100720,
    100721,
    100727,
    100728,
    100729,
    100736,
    100737,
    100738,
    100739,
    100740,
    100742,
    100743,
    100744,
    100747,
    100749,
    100752,
    100755,
    100756,
    100759,
    100762,
    100764,
    100765,
    100766,
    100767,
    100768,
    100769,
    100770,
    100771,
    100772,
    100773,
    100776,
    100779,
    100781,
    100783,
    100785,
    100789,
    100790,
    100791,
    100792,
    100796,
    100803,
    100804
  );
  script_xref(name:"MSKB", value:"4038781");
  script_xref(name:"MSFT", value:"MS17-4038781");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"KB4038781: Windows 10 September 2017 Cumulative Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4038781.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists when
    Microsoft Windows PDF Library improperly handles objects
    in memory. The vulnerability could corrupt memory in a
    way that enables an attacker to execute arbitrary code
    in the context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user. If the current
    user is logged on with administrative user rights, an
    attacker could take control of an affected system. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts with full user
    rights.  (CVE-2017-8728, CVE-2017-8737)

  - An information disclosure vulnerability exists when
    Windows Hyper-V on a host operating system fails to
    properly validate input from an authenticated user on a
    guest operating system.  (CVE-2017-8706, CVE-2017-8707,
    CVE-2017-8713)

  - An information disclosure vulnerability exists when the
    Microsoft Windows Graphics Component improperly handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could obtain information to
    further compromise the users system.  (CVE-2017-8683)

  - An Information disclosure vulnerability exists in
    Windows kernel that could allow an attacker to retrieve
    information that could lead to a Kernel Address Space
    Layout Randomization (KASLR) bypass. An attacker who
    successfully exploited this vulnerability could retrieve
    the memory address of a kernel object.  (CVE-2017-8687)

  - A remote code execution vulnerability exists when
    Microsoft Edge improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that enables an attacker to execute arbitrary code in
    the context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2017-8734)

  - An information disclosure vulnerability exists in the
    way that the Windows Graphics Device Interface (GDI)
    handles objects in memory, allowing an attacker to
    retrieve information from a targeted system. By itself,
    the information disclosure does not allow arbitrary code
    execution; however, it could allow arbitrary code to be
    run if the attacker uses it in combination with another
    vulnerability.  (CVE-2017-8676)

  - A remote code execution vulnerability exists in the way
    that Microsoft browser JavaScript engines render content
    when handling objects in memory. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. In a web-based attack scenario, an attacker could
    host a specially crafted website that is designed to
    exploit the vulnerability through Microsoft browsers and
    then convince a user to view the website. An attacker
    could also embed an ActiveX control marked &quot;safe
    for initialization&quot; in an application or Microsoft
    Office document that hosts the related rendering engine.
    The attacker could also take advantage of compromised
    websites, and websites that accept or host user-provided
    content or advertisements. These websites could contain
    specially crafted content that could exploit the
    vulnerability. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2017-8741, CVE-2017-8748)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Microsoft Edge. The vulnerability could corrupt memory
    in such a way that an attacker could execute arbitrary
    code in the context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2017-8738,
    CVE-2017-8753, CVE-2017-8756)

  - A race condition that could lead to a remote code
    execution vulnerability exists in NetBT Session Services
    when NetBT fails to maintain certain sequencing
    requirements.  (CVE-2017-0161)

  - A remote code execution vulnerability exists in the way
    Microsoft Edge handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2017-8757)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user.  (CVE-2017-8747,
    CVE-2017-8749)

  - An elevation of privilege vulnerability exists in
    Windows when the Win32k component fails to properly
    handle objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2017-8720)

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

  - An information disclosure vulnerability exists when
    Microsoft Edge improperly handles clipboard events. For
    an attack to be successful, an attacker must persuade a
    user to visit a malicious website and leave it open
    during clipboard activities. The update addresses the
    vulnerability by changing how Microsoft Edge handles
    clipboard events in the browser. (CVE-2017-8643)

  - A spoofing vulnerability exists in Microsoft's
    implementation of the Bluetooth stack. An attacker who
    successfully exploited this vulnerability could perform
    a man-in-the-middle attack and force a user's computer
    to unknowingly route traffic through the attacker's
    computer. The attacker can then monitor and read the
    traffic before sending it on to the intended recipient.
    (CVE-2017-8628)

  - An information disclosure vulnerability exists in
    Microsoft browsers due to improper parent domain
    verification in certain functionality. An attacker who
    successfully exploited the vulnerability could obtain
    specific information that is used in the parent domain.
    (CVE-2017-8736)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2017-8678, CVE-2017-8679, CVE-2017-8709,
    CVE-2017-8719)

  - A vulnerability exists when Microsoft Edge improperly
    accesses objects in memory. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user.  (CVE-2017-11766)

  - A security feature bypass exists in Microsoft Edge when
    the Edge Content Security Policy (CSP) fails to properly
    validate certain specially crafted documents. An
    attacker who exploited the bypass could trick a user
    into loading a page containing malicious content.
    (CVE-2017-8723, CVE-2017-8754)

  - A remote code execution vulnerability exists when
    Microsoft .NET Framework processes untrusted input. An
    attacker who successfully exploited this vulnerability
    in software using the .NET framework could take control
    of an affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights. Users whose accounts are
    configured to have fewer user rights on the system could
    be less impacted than users who operate with
    administrative user rights.  (CVE-2017-8759)

  - A information disclosure vulnerability exists when the
    Windows GDI+ component improperly discloses kernel
    memory addresses. An attacker who successfully exploited
    the vulnerability could obtain information to further
    compromise the users system.  (CVE-2017-8677,
    CVE-2017-8681)

  - An information disclosure vulnerability exists in the
    way that the Windows Graphics Device Interface (GDI)
    handles objects in memory, allowing an attacker to
    retrieve information from a targeted system. By itself,
    the information disclosure does not allow arbitrary code
    execution; however, it could allow arbitrary code to be
    run if the attacker uses it in combination with another
    vulnerability.  (CVE-2017-8688)

  - A remote code execution vulnerability exists due to the
    way Windows Uniscribe handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could take control of the affected system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2017-8692)

  - An elevation of privilege vulnerability exists in
    Windows when the Windows kernel-mode driver fails to
    properly handle objects in memory. An attacker who
    successfully exploited this vulnerability could run
    arbitrary code in kernel mode. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2017-8675)

  - A spoofing vulnerability exists when Microsoft Edge does
    not properly parse HTTP content. An attacker who
    successfully exploited this vulnerability could trick a
    user by redirecting the user to a specially crafted
    website. The specially crafted website could either
    spoof content or serve as a pivot to chain an attack
    with other vulnerabilities in web services.
    (CVE-2017-8735)

  - A spoofing vulnerability exists when Internet Explorer
    improperly handles specific HTML content. An attacker
    who successfully exploited this vulnerability could
    trick a user into believing that the user was visiting a
    legitimate website. The specially crafted website could
    either spoof content or serve as a pivot to chain an
    attack with other vulnerabilities in web services.
    (CVE-2017-8733)

  - A remote code execution vulnerability exists when
    Microsoft browsers improperly access objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user.  (CVE-2017-8750)

  - An information disclosure vulnerability exists when the
    Windows kernel fails to properly initialize a memory
    address, allowing an attacker to retrieve information
    that could lead to a Kernel Address Space Layout
    Randomization (KASLR) bypass. An attacker who
    successfully exploited this vulnerability could retrieve
    the base address of the kernel driver from a compromised
    process.  (CVE-2017-8708)

  - A remote code execution vulnerability exists when the
    Windows font library improperly handles specially
    crafted embedded fonts. An attacker who successfully
    exploited this vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2017-8682)

  - An elevation of privilege vulnerability exists in
    Windows Error Reporting (WER) when WER handles and
    executes files. The vulnerability could allow elevation
    of privilege if an attacker can successfully exploit it.
    An attacker who successfully exploited the vulnerability
    could gain greater access to sensitive information and
    system functionality.  (CVE-2017-8702)

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
    with administrative user rights.  (CVE-2017-8699)
    
  - An information disclosure vulnerability exists in
    Microsoft browsers in the scripting engines due to
    improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a specially crafted website,
    to disclose files on a user's computer. (CVE-2017-8529)");
  # https://support.microsoft.com/en-us/help/4038781/windows-10-update-kb4038781
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c29dee1");
  script_set_attribute(attribute:"solution", value:
"Apply security update KB4038781.");
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
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/03");

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
kbs = make_list('4038781');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
os_name = get_kb_item_or_exit("SMB/ProductName");

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if("LTSB" >!< os_name) audit(AUDIT_OS_NOT, "Windows 10 version 1507 LTSB");

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"10240",
                   rollup_date:"09_2017",
                   bulletin:bulletin,
                   rollup_kb_list:[4038781])
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
