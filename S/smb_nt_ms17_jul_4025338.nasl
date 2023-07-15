#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#
include("compat.inc");

if (description)
{
  script_id(104383);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/18");

  script_cve_id(
    "CVE-2017-0170",
    "CVE-2017-8463",
    "CVE-2017-8467",
    "CVE-2017-8486",
    "CVE-2017-8495",
    "CVE-2017-8556",
    "CVE-2017-8557",
    "CVE-2017-8561",
    "CVE-2017-8562",
    "CVE-2017-8563",
    "CVE-2017-8564",
    "CVE-2017-8565",
    "CVE-2017-8573",
    "CVE-2017-8577",
    "CVE-2017-8578",
    "CVE-2017-8580",
    "CVE-2017-8581",
    "CVE-2017-8582",
    "CVE-2017-8585",
    "CVE-2017-8587",
    "CVE-2017-8588",
    "CVE-2017-8589",
    "CVE-2017-8590",
    "CVE-2017-8592",
    "CVE-2017-8595",
    "CVE-2017-8599",
    "CVE-2017-8601",
    "CVE-2017-8602",
    "CVE-2017-8605",
    "CVE-2017-8606",
    "CVE-2017-8607",
    "CVE-2017-8608",
    "CVE-2017-8609",
    "CVE-2017-8611",
    "CVE-2017-8618",
    "CVE-2017-8619"
  );
  script_bugtraq_id(
    99387,
    99388,
    99389,
    99390,
    99391,
    99392,
    99393,
    99394,
    99396,
    99397,
    99398,
    99399,
    99400,
    99402,
    99403,
    99408,
    99409,
    99410,
    99412,
    99413,
    99414,
    99416,
    99418,
    99419,
    99420,
    99421,
    99423,
    99424,
    99425,
    99426,
    99427,
    99428,
    99429,
    99431,
    99432,
    99439
  );
  script_xref(name:"MSKB", value:"4025338");
  script_xref(name:"MSFT", value:"MS17-4025338");

  script_name(english:"KB4025338: Windows 10 July 2017 Cumulative Update");
  script_summary(english:"Checks for rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4025338.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists when
    Windows Search handles objects in memory. An attacker
    who successfully exploited this vulnerability could take
    control of the affected system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2017-8589)

  - A remote code execution vulnerability exists in the way
    that the VBScript engine, when rendered in Internet
    Explorer, handles objects in memory. In a web-based
    attack scenario, an attacker could host a specially
    crafted website that is designed to exploit this
    vulnerability through Internet Explorer and then
    convince a user to view the website. An attacker could
    also embed an ActiveX control marked &quot;safe for
    initialization in an application or Microsoft
    Office document that hosts the Internet Explorer
    rendering engine. The attacker could also take advantage
    of compromised websites and websites that accept or host
    user-provided content or advertisements. These websites
    could contain specially crafted content that could
    exploit this vulnerability. An attacker who successfully
    exploited this vulnerability could gain the same user
    rights as the current user.  (CVE-2017-8618)

  - An elevation of privilege vulnerability exists in
    Windows when the Win32k component fails to properly
    handle objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2017-8467, CVE-2017-8556,
    CVE-2017-8573, CVE-2017-8577, CVE-2017-8578,
    CVE-2017-8580)

  - A Denial Of Service vulnerability exists when Windows
    Explorer attempts to open a non-existent file. An
    attacker who successfully exploited this vulnerability
    could cause a denial of service. A attacker could
    exploit this vulnerability by hosting a specially
    crafted web site and convince a user to browse to the
    page, containing the reference to the non-existing file,
    and cause the victim's system to stop responding. An
    attacker could not force a user to view the attacker-
    controlled content. Instead, an attacker would have to
    convince a user to take action. For example, an attacker
    could trick a user into clicking a link that takes the
    user to the attacker's site The update addresses the
    vulnerability by correcting how Windows Explorer handles
    open attempts for non-existent files. (CVE-2017-8587)

  - A remote code execution vulnerability exists in the way
    JavaScript engines render when handling objects in
    memory in Microsoft browsers. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. An attacker who successfully exploited the
    vulnerability could gain the same user rights as the
    current user.  (CVE-2017-8606, CVE-2017-8607,
    CVE-2017-8608)

  - A security feature bypass vulnerability exists in
    Microsoft Windows when Kerberos fails to prevent
    tampering with the SNAME field during ticket exchange.
    An attacker who successfully exploited this
    vulnerability could use it to bypass Extended Protection
    for Authentication.  (CVE-2017-8495)

  - A remote code execution vulnerability exists in the way
    that the Scripting Engine renders when handling objects
    in memory in Microsoft browsers. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user.  (CVE-2017-8609)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Kernel handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2017-8561)

  - A remote code execution vulnerability exists in
    PowerShell when PSObject wraps a CIM Instance. An
    attacker who successfully exploited this vulnerability
    could execute malicious code on a vulnerable system. In
    an attack scenario, an attacker could execute malicious
    code in a PowerShell remote session. The update
    addresses the vulnerability by correcting how PowerShell
    deserializes user supplied scripts. (CVE-2017-8565)

  - An elevation of privilege vulnerability exists when
    Windows improperly handles calls to Advanced Local
    Procedure Call (ALPC). An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    the security context of the local system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2017-8562)

  - An information disclosure vulnerability exists in
    Microsoft Windows when Win32k fails to properly handle
    objects in memory. An attacker who successfully
    exploited the vulnerability could obtain information to
    further compromise the users system.  (CVE-2017-8486)

  - An information disclosure vulnerability exists in the
    Windows Performance Monitor Console when it improperly
    parses XML input containing a reference to an external
    entity. An attacker who successfully exploited this
    vulnerability could read arbitrary files via an XML
    external entity (XXE) declaration.  (CVE-2017-0170)

  - A remote code execution vulnerability exists in the way
    Microsoft Edge handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2017-8595, CVE-2017-8605,
    CVE-2017-8619)

  - An elevation of privilege vulnerability exists when the
    Windows Common Log File System (CLFS) driver improperly
    handles objects in memory.  (CVE-2017-8590)

  - An information disclosure vulnerability exists when the
    Windows kernel fails to properly initialize a memory
    address, allowing an attacker to retrieve information
    that could lead to a Kernel Address Space Layout
    Randomization (KASLR) bypass. An attacker who
    successfully exploited this vulnerability could retrieve
    the base address of the kernel driver from a compromised
    process.  (CVE-2017-8564)

  - A security feature bypass vulnerability exists when
    Microsoft Browsers improperly handle redirect requests.
    This vulnerability allows Microsoft Browsers to bypass
    CORS redirect restrictions and to follow redirect
    requests that should otherwise be ignored. An attacker
    who successfully exploited this vulnerability could
    force the browser to send data that would otherwise be
    restricted to a destination web site of their choice.
    (CVE-2017-8592)

  - An Information Disclosure vulnerability exists when the
    HTTP.sys server application component improperly handles
    objects in memory. An attacker who successfully
    exploited this vulnerability could obtain information to
    further compromise the HTTP.sys server application
    system. A remote unauthenticated attacker could exploit
    this vulnerability by issuing a request to the HTTP.sys
    server application. The update addresses the
    vulnerability by correcting how the HTTP.sys server
    application handles objects in memory. (CVE-2017-8582)

  - A spoofing vulnerability exists when an affected
    Microsoft browser does not properly parse HTTP content.
    An attacker who successfully exploited this
    vulnerability could trick a user by redirecting the user
    to a specially crafted website. The specially crafted
    website could either spoof content or serve as a pivot
    to chain an attack with other vulnerabilities in web
    services.  (CVE-2017-8602)

  - A denial of service vulnerability exists when Microsoft
    Common Object Runtime Library improperly handles web
    requests. An attacker who successfully exploited this
    vulnerability could cause a denial of service against a
    .NET web application. A remote unauthenticated attacker
    could exploit this vulnerability by issuing specially
    crafted requests to the .NET application. The update
    addresses the vulnerability by correcting how the .NET
    web application handles web requests. (CVE-2017-8585)

  - An elevation of privilege vulnerability exists when
    Windows improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could run processes in an elevated context.
    (CVE-2017-8581)

  - An elevation of privilege vulnerability exists in
    Microsoft Windows when a man-in-the-middle attacker is
    able to successfully forward an authentication request
    to a Windows LDAP server, such as a system running
    Active Directory Domain Services (AD DS) or Active
    Directory Lightweight Directory Services (AD LDS), which
    has been configured to require signing or sealing on
    incoming connections. The update addresses this
    vulnerability by incorporating support for Extended
    Protection for Authentication security feature, which
    allows the LDAP server to detect and block such
    forwarded authentication requests once enabled.
    (CVE-2017-8563)

  - A spoofing vulnerability exists when Microsoft Edge
    improperly handles specific HTML content. An attacker
    who successfully exploited this vulnerability could
    trick a user into believing that the user was on a
    legitimate website. The specially crafted website could
    either spoof content or serve as a pivot to chain an
    attack with other vulnerabilities in web services.
    (CVE-2017-8611)

  - A security feature bypass vulnerability exists when
    Microsoft Edge fails to correctly apply Same Origin
    Policy for HTML elements present in other browser
    windows. An attacker could use this vulnerability to
    trick a user into loading a page with malicious content.
    (CVE-2017-8599)

  - A remote code execution vulnerability exists in the way
    that Microsoft WordPad parses specially crafted files.
    Exploitation of this vulnerability requires that a user
    open a specially crafted file with an affected version
    of Microsoft WordPad.  (CVE-2017-8588)

  - A remote code execution vulnerability exists when
    Windows Explorer improperly handles executable files and
    shares during rename operations. An attacker who
    successfully exploited this vulnerability could run
    arbitrary code in the context of another user. Users not
    running as administrators would be less affected.
    (CVE-2017-8463)

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
    current user.  (CVE-2017-8601)

  - An information disclosure vulnerability exists in the
    Windows System Information Console when it improperly
    parses XML input containing a reference to an external
    entity. An attacker who successfully exploited this
    vulnerability could read arbitrary files via an XML
    external entity (XXE) declaration.  (CVE-2017-8557)");
  # https://support.microsoft.com/en-us/help/4025338/windows-10-update-kb4025338
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa6f9fa1");
  script_set_attribute(attribute:"solution", value:
"Apply security update KB4025338.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2020 Tenable Network Security, Inc.");

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

bulletin = "MS17-07";
kbs = make_list('4025338');

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
                   rollup_date:"07_2017",
                   bulletin:bulletin,
                   rollup_kb_list:[4025338])
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
