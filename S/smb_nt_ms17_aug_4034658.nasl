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
  script_id(102264);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/18");

  script_cve_id(
    "CVE-2017-0174",
    "CVE-2017-0250",
    "CVE-2017-0293",
    "CVE-2017-8503",
    "CVE-2017-8591",
    "CVE-2017-8593",
    "CVE-2017-8620",
    "CVE-2017-8623",
    "CVE-2017-8624",
    "CVE-2017-8625",
    "CVE-2017-8633",
    "CVE-2017-8635",
    "CVE-2017-8636",
    "CVE-2017-8639",
    "CVE-2017-8640",
    "CVE-2017-8641",
    "CVE-2017-8644",
    "CVE-2017-8645",
    "CVE-2017-8646",
    "CVE-2017-8652",
    "CVE-2017-8653",
    "CVE-2017-8655",
    "CVE-2017-8656",
    "CVE-2017-8657",
    "CVE-2017-8661",
    "CVE-2017-8664",
    "CVE-2017-8666",
    "CVE-2017-8669",
    "CVE-2017-8670",
    "CVE-2017-8671",
    "CVE-2017-8672"
  );
  script_bugtraq_id(
    98100,
    99395,
    99430,
    100027,
    100032,
    100033,
    100034,
    100035,
    100037,
    100038,
    100039,
    100042,
    100044,
    100047,
    100050,
    100051,
    100052,
    100053,
    100055,
    100056,
    100057,
    100059,
    100061,
    100063,
    100068,
    100069,
    100070,
    100071,
    100072,
    100085,
    100089
  );
  script_xref(name:"MSKB", value:"4034658");
  script_xref(name:"MSFT", value:"MS17-4034658");

  script_name(english:"KB4034658: Windows 10 Version 1607 and Windows Server 2016 August 2017 Cumulative Update");
  script_summary(english:"Checks for rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4034658.
It is, therefore, affected by multiple vulnerabilities :

  - A denial of service vulnerability exists when Microsoft
    Windows improperly handles NetBIOS packets. An attacker
    who successfully exploited this vulnerability could
    cause a target computer to become completely
    unresponsive. A remote unauthenticated attacker could
    exploit this vulnerability by sending a series of TCP
    packets to a target system, resulting in a permanent
    denial of service condition. The update addresses the
    vulnerability by correcting how the Windows network
    stack handles NetBIOS traffic. (CVE-2017-0174)

  - A buffer overflow vulnerability exists in the Microsoft
    JET Database Engine that could allow remote code
    execution on an affected system. An attacker who
    successfully exploited this vulnerability could take
    complete control of an affected system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2017-0250)

  - A remote code execution vulnerability exists when
    Microsoft Windows PDF Library improperly handles objects
    in memory. The vulnerability could corrupt memory in a
    way that enables an attacker to execute arbitrary code
    in the context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user. (CVE-2017-0293)

  - An elevation of privilege vulnerability exists in
    Microsoft Edge that could allow an attacker to escape
    from the AppContainer sandbox in the browser. An
    attacker who successfully exploited this vulnerability
    could gain elevated privileges and break out of the Edge
    AppContainer sandbox.The vulnerability by itself does
    not allow arbitrary code to run. However, this
    vulnerability could be used in conjunction with one or
    more vulnerabilities (for example a remote code
    execution vulnerability and another elevation of
    privilege vulnerability) to take advantage of the
    elevated privileges when running.The security update
    addresses the vulnerability by modifying how Microsoft
    Edge handles sandboxing. (CVE-2017-8503)

  - A remote code execution vulnerability exists in Windows
    Input Method Editor (IME) when IME improperly handles
    parameters in a method of a DCOM class. The DCOM server
    is a Windows component installed regardless of which
    languages/IMEs are enabled. An attacker can instantiate
    the DCOM class and exploit the system even if IME is not
    enabled. (CVE-2017-8591)

  - An elevation of privilege vulnerability exists in
    Windows when the Win32k component fails to properly
    handle objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights. (CVE-2017-8593)

  - A remote code execution vulnerability exists when
    Windows Search handles objects in memory. An attacker
    who successfully exploited this vulnerability could take
    control of the affected system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.To exploit the
    vulnerability, the attacker could send specially crafted
    messages to the Windows Search service. An attacker with
    access to a target computer could exploit this
    vulnerability to elevate privileges and take control of
    the computer. Additionally, in an enterprise scenario, a
    remote unauthenticated attacker could remotely trigger
    the vulnerability through an SMB connection and then
    take control of a target computer.The security update
    addresses the vulnerability by correcting how Windows
    Search handles objects in memory. (CVE-2017-8620)

  - A denial of service vulnerability exists when Microsoft
    Hyper-V Network Switch on a host server fails to
    properly validate input from a privileged user on a
    guest operating system. An attacker who successfully
    exploited the vulnerability could cause the host server
    to crash. (CVE-2017-8623)

  - An elevation of privilege vulnerability exists when the
    Windows Common Log File System (CLFS) driver improperly
    handles objects in memory.(CVE-2017-8624)

  - A security feature bypass vulnerability exists when
    Internet Explorer fails to validate User Mode Code
    Integrity (UMCI) policies. The vulnerability could allow
    an attacker to bypass Device Guard UCMI policies.To
    exploit the vulnerability, a user could either visit a
    malicious website or an attacker with access to the
    system could run a specially crafted application. An
    attacker could then leverage the vulnerability to run
    unsigned malicious code as though it were signed by a
    trusted source.The update addresses the vulnerability by
    correcting how Internet Explorer validates UMCI
    policies. (CVE-2017-8625)

  - This security update resolves a vulnerability in Windows
    Error Reporting (WER). The vulnerability could allow
    elevation of privilege if successfully exploited by an
    attacker. An attacker who successfully exploited this
    vulnerability could gain greater access to sensitive
    information and system functionality. This update
    corrects the way the WER handles and executes files.
    (CVE-2017-8633)

  - A remote code execution vulnerability exists in the way
    JavaScript engines render when handling objects in
    memory in Microsoft browsers. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. An attacker who successfully exploited the
    vulnerability could gain the same user rights as the
    current user. (CVE-2017-8635)

  - A remote code execution vulnerability exists in the way
    that Microsoft browser JavaScript engines render content
    when handling objects in memory. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. (CVE-2017-8636)

  - A remote code execution vulnerability exists in the way
    that Microsoft browser JavaScript engines render content
    when handling objects in memory. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. (CVE-2017-8639)

  - A remote code execution vulnerability exists in the way
    that Microsoft browser JavaScript engines render content
    when handling objects in memory. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. (CVE-2017-8640)

  - A remote code execution vulnerability exists in the way
    JavaScript engines render when handling objects in
    memory in Microsoft browsers. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. An attacker who successfully exploited the
    vulnerability could gain the same user rights as the
    current user. (CVE-2017-8641)

  - An information disclosure vulnerability exists when
    Microsoft Edge improperly handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system. (CVE-2017-8644)

  - A remote code execution vulnerability exists in the way
    that Microsoft browser JavaScript engines render content
    when handling objects in memory. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. (CVE-2017-8645)

  - A remote code execution vulnerability exists in the way
    that Microsoft browser JavaScript engines render content
    when handling objects in memory. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. (CVE-2017-8646)

  - An information disclosure vulnerability exists when
    Microsoft Edge improperly handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system. (CVE-2017-8652)

  - A remote code execution vulnerability exists when
    Microsoft browsers improperly access objects in memory.
    The vulnerability could corrupt memory in such a way
    that enables an attacker to execute arbitrary code in
    the context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user. (CVE-2017-8653)

  - A remote code execution vulnerability exists in the way
    that Microsoft browser JavaScript engines render content
    when handling objects in memory. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. (CVE-2017-8655)

  - A remote code execution vulnerability exists in the way
    that Microsoft browser JavaScript engines render content
    when handling objects in memory. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. (CVE-2017-8656)

  - A remote code execution vulnerability exists in the way
    that Microsoft browser JavaScript engines render content
    when handling objects in memory. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. (CVE-2017-8657)

  - A remote code execution vulnerability exists in the way
    affected Microsoft scripting engines render when
    handling objects in memory. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. An attacker who successfully exploited the
    vulnerability could gain the same user rights as the
    current user. (CVE-2017-8661)

  - A remote code execution vulnerability exists when
    Windows Hyper-V on a host server fails to properly
    validate input from an authenticated user on a guest
    operating system. (CVE-2017-8664)

  - An information disclosure vulnerability exists when the
    win32k component improperly provides kernel information.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system. (CVE-2017-8666)

  - A remote code execution vulnerability exists in the way
    Microsoft browsers handle objects in memory while
    rendering content. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user. If
    the current user is logged on with administrative user
    rights, an attacker who successfully exploited the
    vulnerability could take control of an affected system.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights. (CVE-2017-8669)

  - A remote code execution vulnerability exists in the way
    that Microsoft browser JavaScript engines render content
    when handling objects in memory. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. (CVE-2017-8670)

  - A remote code execution vulnerability exists in the way
    that Microsoft browser JavaScript engines render content
    when handling objects in memory. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. (CVE-2017-8671)

  - A remote code execution vulnerability exists in the way
    that Microsoft browser JavaScript engines render content
    when handling objects in memory. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. (CVE-2017-8672)");
  # https://support.microsoft.com/en-us/help/4034658/windows-10-update-kb4034658
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b993cd6");
  script_set_attribute(attribute:"solution", value:
"Apply security update KB4034658.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8620");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS17-08";
kbs = make_list('4034658');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_nano() == 1) audit(AUDIT_OS_NOT, "a currently supported OS (Windows Nano Server)");

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"14393",
                   rollup_date:"08_2017",
                   bulletin:bulletin,
                   rollup_kb_list:[4034658])
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
