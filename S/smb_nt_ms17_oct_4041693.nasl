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
  script_id(103750);
  script_version("1.20");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-8689",
    "CVE-2017-8694",
    "CVE-2017-8717",
    "CVE-2017-8718",
    "CVE-2017-8727",
    "CVE-2017-11762",
    "CVE-2017-11763",
    "CVE-2017-11765",
    "CVE-2017-11771",
    "CVE-2017-11772",
    "CVE-2017-11779",
    "CVE-2017-11780",
    "CVE-2017-11781",
    "CVE-2017-11783",
    "CVE-2017-11784",
    "CVE-2017-11785",
    "CVE-2017-11790",
    "CVE-2017-11793",
    "CVE-2017-11810",
    "CVE-2017-11813",
    "CVE-2017-11814",
    "CVE-2017-11815",
    "CVE-2017-11816",
    "CVE-2017-11817",
    "CVE-2017-11818",
    "CVE-2017-11822",
    "CVE-2017-11824",
    "CVE-2017-13080"
  );
  script_bugtraq_id(
    101077,
    101081,
    101083,
    101093,
    101094,
    101095,
    101099,
    101100,
    101101,
    101108,
    101109,
    101110,
    101111,
    101114,
    101116,
    101122,
    101128,
    101136,
    101140,
    101141,
    101142,
    101144,
    101147,
    101149,
    101161,
    101162,
    101166,
    101274
  );
  script_xref(name:"MSKB", value:"4041687");
  script_xref(name:"IAVA", value:"2017-A-0310");
  script_xref(name:"MSKB", value:"4041693");
  script_xref(name:"MSFT", value:"MS17-4041687");
  script_xref(name:"MSFT", value:"MS17-4041693");

  script_name(english:"Windows 8.1 and Windows Server 2012 R2 October 2017 Security Updates (KRACK)");
  script_summary(english:"Checks for rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4041687
or cumulative update 4041693. It is, therefore, affected by
multiple vulnerabilities :

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory
    via the Microsoft Windows Text Services Framework. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2017-8727)

  - A remote code execution vulnerability exists when
    Windows Search handles objects in memory. An attacker
    who successfully exploited this vulnerability could take
    control of the affected system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2017-11771)

  - An elevation of privilege vulnerability exists when the
    Windows Graphics Component improperly handles objects in
    memory. An attacker who successfully exploited this
    vulnerability could run processes in an elevated
    context.  (CVE-2017-11824)

  - An elevation of privilege vulnerability exists when the
    Windows kernel-mode driver fails to properly handle
    objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2017-8689, CVE-2017-8694)

  - A buffer overflow vulnerability exists in the Microsoft
    JET Database Engine that could allow remote code
    execution on an affected system. An attacker who
    successfully exploited this vulnerability could take
    control of an affected system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights. Users whose
    accounts are configured to have fewer user rights on the
    system could be less impacted than users who operate
    with administrative user rights.  (CVE-2017-8717,
    CVE-2017-8718)

  - An information disclosure vulnerability exists in the
    way that the Windows Graphics Device Interface (GDI)
    handles objects in memory, allowing an attacker to
    retrieve information from a targeted system. By itself,
    the information disclosure does not allow arbitrary code
    execution; however, it could allow arbitrary code to be
    run if the attacker uses it in combination with another
    vulnerability.  (CVE-2017-11816)

  - An information disclosure vulnerability exists in the
    way that the Windows SMB Server handles certain
    requests. An authenticated attacker who successfully
    exploited this vulnerability could craft a special
    packet, which could lead to information disclosure from
    the server.  (CVE-2017-11815)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2017-11765, CVE-2017-11814)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2017-11793, CVE-2017-11810)

  - A remote code execution vulnerability exists when the
    Windows font library improperly handles specially
    crafted embedded fonts. An attacker who successfully
    exploited the vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2017-11762,
    CVE-2017-11763)

  - An information disclosure vulnerability exists when
    Internet Explorer improperly handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2017-11790)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly initializes objects in memory.
    (CVE-2017-11817)

  - A denial of service vulnerability exists in the
    Microsoft Server Block Message (SMB) when an attacker
    sends specially crafted requests to the server. An
    attacker who exploited this vulnerability could cause
    the affected system to crash. To attempt to exploit this
    issue, an attacker would need to send specially crafted
    SMB requests to the target system. Note that the denial
    of service vulnerability would not allow an attacker to
    execute code or to elevate their user rights, but it
    could cause the affected system to stop accepting
    requests. The security update addresses the
    vulnerability by correcting the manner in which SMB
    handles specially crafted client requests.
    (CVE-2017-11781)

  - An elevation of privilege vulnerability exists when
    Windows improperly handles calls to Advanced Local
    Procedure Call (ALPC). An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    the security context of the local system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2017-11783)

  - An Information disclosure vulnerability exists when
    Windows Search improperly handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2017-11772)

  - An Security Feature bypass vulnerability exists in
    Microsoft Windows storage when it fails to validate an
    integrity-level check. An attacker who successfully
    exploited the vulnerability could allow an application
    with a certain integrity level to execute code at a
    different integrity level. The update addresses the
    vulnerability by correcting how Microsoft storage
    validates an integrity-level check. (CVE-2017-11818)

  - A remote code execution vulnerability exists in the way
    that the Microsoft Server Message Block 1.0 (SMBv1)
    server handles certain requests. An attacker who
    successfully exploited the vulnerability could gain the
    ability to execute code on the target server.
    (CVE-2017-11780)

  - A remote code execution vulnerability
    exists in Windows Domain Name System (DNS) DNSAPI.dll
    when it fails to properly handle DNS responses. An
    attacker who successfully exploited the vulnerability
    could run arbitrary code in the context of the Local
    System Account.  (CVE-2017-11779)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2017-11813,
    CVE-2017-11822)

  - An information disclosure vulnerability exists in the
    Windows kernel that could allow an attacker to retrieve
    information that could lead to a Kernel Address Space
    Layout Randomization (ASLR) bypass. An attacker who
    successfully exploited the vulnerability could retrieve
    the memory address of a kernel object.  (CVE-2017-11784,
    CVE-2017-11785)

  - A spoofing vulnerability exists in the Windows
    implementation of wireless networking. An attacker who
    successfully exploited this vulnerability could
    potentially replay broadcast and/or multicast traffic
    to hosts on a WPA or WPA 2-protected wireless network.
    (CVE-2017-13080)");
  # https://support.microsoft.com/en-us/help/4041687/windows-81-update-kb4041687
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1c67d5c");
  # https://support.microsoft.com/en-us/help/4041693/windows-81-update-kb4041693
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c3325f2");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB4041687 or Cumulative update KB4041693.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11771");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS17-10";
kbs = make_list('4041687', '4041693');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Windows 8 EOL
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"6.3",
                   sp:0,
                   rollup_date:"10_2017",
                   bulletin:bulletin,
                   rollup_kb_list:[4041687, 4041693])
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
