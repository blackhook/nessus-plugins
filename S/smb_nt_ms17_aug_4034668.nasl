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
  script_id(104382);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/18");

  script_cve_id(
    "CVE-2017-0174",
    "CVE-2017-0250",
    "CVE-2017-0293",
    "CVE-2017-8591",
    "CVE-2017-8593",
    "CVE-2017-8620",
    "CVE-2017-8624",
    "CVE-2017-8625",
    "CVE-2017-8633",
    "CVE-2017-8635",
    "CVE-2017-8636",
    "CVE-2017-8640",
    "CVE-2017-8641",
    "CVE-2017-8644",
    "CVE-2017-8652",
    "CVE-2017-8653",
    "CVE-2017-8655",
    "CVE-2017-8664",
    "CVE-2017-8666",
    "CVE-2017-8669",
    "CVE-2017-8672"
  );
  script_bugtraq_id(
    98100,
    99430,
    100027,
    100032,
    100034,
    100038,
    100039,
    100044,
    100047,
    100051,
    100055,
    100056,
    100057,
    100059,
    100061,
    100063,
    100068,
    100069,
    100072,
    100085,
    100089
  );
  script_xref(name:"MSKB", value:"4034668");
  script_xref(name:"MSFT", value:"MS17-4034668");

  script_name(english:"KB4034668: Windows 10 August 2017 Cumulative Update");
  script_summary(english:"Checks for rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4034668. 
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists when
    Windows Search handles objects in memory. An attacker
    who successfully exploited this vulnerability could take
    control of the affected system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2017-8620)

  - An elevation of privilege vulnerability exists when the
    Windows Common Log File System (CLFS) driver improperly
    handles objects in memory.  (CVE-2017-8624)

  - A remote code execution vulnerability exists in the way
    JavaScript engines render when handling objects in
    memory in Microsoft browsers. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. An attacker who successfully exploited the
    vulnerability could gain the same user rights as the
    current user.  (CVE-2017-8635, CVE-2017-8641)

  - An information disclosure vulnerability exists when the
    win32k component improperly provides kernel information.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2017-8666)

  - A security feature bypass vulnerability exists when
    Internet Explorer fails to validate User Mode Code
    Integrity (UMCI) policies. The vulnerability could allow
    an attacker to bypass Device Guard UMCI policies.
    (CVE-2017-8625)

  - A remote code execution vulnerability exists in Windows
    Input Method Editor (IME) when IME improperly handles
    parameters in a method of a DCOM class. The DCOM server
    is a Windows component installed regardless of which
    languages/IMEs are enabled. An attacker can instantiate
    the DCOM class and exploit the system even if IME is not
    enabled.  (CVE-2017-8591)

  - A remote code execution vulnerability exists when
    Windows Hyper-V on a host server fails to properly
    validate input from an authenticated user on a guest
    operating system.  (CVE-2017-8664)

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
    control of an affected system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights. Users whose
    accounts are configured to have fewer user rights on the
    system could be less impacted than users who operate
    with administrative user rights.  (CVE-2017-0250)

  - A remote code execution vulnerability exists in the way
    Microsoft browsers handle objects in memory while
    rendering content. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2017-8669)

  - An elevation of privilege vulnerability exists in
    Windows Error Reporting (WER) when WER handles and
    executes files. The vulnerability could allow elevation
    of privilege if an attacker can successfully exploit it.
    An attacker who successfully exploited the vulnerability
    could gain greater access to sensitive information and
    system functionality.  (CVE-2017-8633)

  - A remote code execution vulnerability exists when
    Microsoft browsers improperly access objects in memory.
    The vulnerability could corrupt memory in such a way
    that enables an attacker to execute arbitrary code in
    the context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2017-8653)

  - An elevation of privilege vulnerability exists in
    Windows when the Win32k component fails to properly
    handle objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2017-8593)

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
    current user.  (CVE-2017-8636, CVE-2017-8640,
    CVE-2017-8655, CVE-2017-8672)

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
    rights.  (CVE-2017-0293)

  - An information disclosure vulnerability exists when
    Microsoft Edge improperly handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2017-8644, CVE-2017-8652)");
  # https://support.microsoft.com/en-us/help/4034668/windows-10-update-kb4034668
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6341411");
  script_set_attribute(attribute:"solution", value:
"Apply security update KB4034668.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8620");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/03");

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
kbs = make_list('4034668');

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
                   rollup_date:"08_2017",
                   bulletin:bulletin,
                   rollup_kb_list:[4034668])
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
