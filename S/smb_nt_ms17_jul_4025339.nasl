#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101366);
  script_version("1.16");
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
    "CVE-2017-8566",
    "CVE-2017-8573",
    "CVE-2017-8574",
    "CVE-2017-8577",
    "CVE-2017-8578",
    "CVE-2017-8580",
    "CVE-2017-8581",
    "CVE-2017-8582",
    "CVE-2017-8584",
    "CVE-2017-8585",
    "CVE-2017-8588",
    "CVE-2017-8589",
    "CVE-2017-8590",
    "CVE-2017-8592",
    "CVE-2017-8595",
    "CVE-2017-8596",
    "CVE-2017-8598",
    "CVE-2017-8599",
    "CVE-2017-8601",
    "CVE-2017-8602",
    "CVE-2017-8603",
    "CVE-2017-8604",
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
    99404,
    99405,
    99406,
    99407,
    99408,
    99409,
    99410,
    99412,
    99414,
    99416,
    99417,
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
    99434,
    99438,
    99439
  );
  script_xref(name:"MSKB", value:"4025339");
  script_xref(name:"MSFT", value:"MS17-4025339");

  script_name(english:"KB4025339: Windows 10 Version 1607 and Windows Server 2016 July 2017 Cumulative Update");
  script_summary(english:"Checks for presence of the patch rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update KB4025339. It is,
therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    Windows Performance Monitor Console due to improper
    parsing of XML input that contains a reference to an
    external entity. An unauthenticated, remote attacker
    can exploit this, by convincing a user to create a
    Data Collector Set and import a specially crafted XML
    file, to disclose arbitrary files via an XML external
    entity (XXE) declaration. (CVE-2017-0170)

  - A remote code execution vulnerability exists in Windows
    Explorer due to improper handling of executable files
    and shares during rename operations. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to open a specially crafted file, to execute arbitrary
    code in the context of the current user. (CVE-2017-8463)

  - Multiple elevation of privilege vulnerabilities exist in
    the Microsoft Graphics component due to improper
    handling of objects in memory. A local attacker can
    exploit these, via a specially crafted application, to
    run arbitrary code in kernel mode. (CVE-2017-8467,
    CVE-2017-8556, CVE-2017-8573, CVE-2017-8574,
    CVE-2017-8577, CVE-2017-8578, CVE-2017-8580)

  - An information disclosure vulnerability exists in Win32k
    due to improper handling of objects in memory. A local
    attacker can exploit this, via a specially crafted
    application, to disclose sensitive information.
    (CVE-2017-8486)

  - A security bypass vulnerability exists in Microsoft
    Windows when handling Kerberos ticket exchanges due to a
    failure to prevent tampering with the SNAME field. A
    man-in-the-middle attacker can exploit this to bypass
    the Extended Protection for Authentication security
    feature. (CVE-2017-8495)

  - An information disclosure vulnerability exists in the
    Windows System Information Console due to improper
    parsing of XML input that contains a reference to an
    external entity. An unauthenticated, remote attacker
    can exploit this, by convincing a user to open a
    specially crafted file, to disclose arbitrary files via
    an XML external entity (XXE) declaration.
    (CVE-2017-8557)

  - An elevation of privilege vulnerability exists in the
    Windows kernel due to improper handling of objects in
    memory. A local attacker can exploit this, via a
    specially crafted application, to execute arbitrary code
    with elevated permissions. (CVE-2017-8561)

  - An elevation of privilege vulnerability exists in
    Windows due to improper handling of calls to Advanced
    Local Procedure Call (ALPC). An authenticated, remote
    attacker can exploit this via a specially crafted
    application, to run processes in an elevated context.
    (CVE-2017-8562)

  - An elevation of privilege vulnerability exists in
    Windows due to Kerberos falling back to NT LAN Manager
    (NTLM) Authentication Protocol as the default
    authentication protocol. An authenticated, remote
    attacker can exploit this, via an application that
    sends specially crafted traffic to a domain controller,
    to run processes in an elevated context.
    (CVE-2017-8563)*

  - An information disclosure vulnerability exists in the
    Windows kernel due to improper initialization of objects
    in memory. An authenticated, remote attacker can exploit
    this, via a specially crafted application, to bypass
    Kernel Address Space Layout Randomization (KASLR) and
    disclose the base address of the kernel driver.
    (CVE-2017-8564)

  - A remote code execution vulnerability exists in
    PowerShell when handling a PSObject that wraps a CIM
    instance. An authenticated, remote attacker can exploit
    this, via a specially crafted script, to execute
    arbitrary code in a PowerShell remote session.
    (CVE-2017-8565)

  - An elevation of privilege vulnerability exists in
    Windows Input Method Editor (IME) due to improper
    handling of parameters in a method of a DCOM class. A
    local attacker can exploit this, via a specially crafted
    application, to run processes in an elevated context.
    (CVE-2017-8566)

  - An elevation of privilege vulnerability exists in
    Windows due to improper handling of objects in memory. A
    local attacker can exploit this, via a specially crafted
    application, to run arbitrary code in kernel mode.
    (CVE-2017-8581)

  - An information disclosure vulnerability exists in the
    HTTP.sys server application component due to improper
    handling of objects in memory. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted request, to disclose sensitive information.
    (CVE-2017-8582)

  - A remote code execution vulnerability exists in
    Microsoft HoloLens due to improper handling of objects
    in memory. An unauthenticated, remote attacker can
    exploit this, via a specially crafted packet, to execute
    arbitrary code. (CVE-2017-8584)

  - A denial of service vulnerability exists in the
    Microsoft Common Runtime Library component due to
    improper handling of web requests. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted request, to cause a denial of service condition
    in a .NET application. (CVE-2017-8585)

  - A remote code execution vulnerability exists in WordPad
    due to improper parsing of specially crafted files. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to open a specially crafted file, to
    execute arbitrary code in the context of the current
    user. (CVE-2017-8588)

  - A remote code execution vulnerability exists in the
    Windows Search component due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit this, by sending specially crafted messages
    to the Windows Search service, to elevate privileges and
    execute arbitrary code. (CVE-2017-8589)

  - An elevation of privilege vulnerability exists in the
    Windows Common Log File System (CLFS) driver due to
    improper handling of objects in memory. A local attacker
    can exploit this, via a specially crafted application,
    to run processes in an elevated context. (CVE-2017-8590)

  - A security bypass vulnerability exists in Microsoft
    browsers due to improper handling of redirect requests.
    An unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a specially crafted website,
    to bypass CORS redirect restrictions. (CVE-2017-8592)

  - Multiple remote code execution vulnerability exist in
    Microsoft Edge in the scripting engine due to improper
    handling of objects in memory. An unauthenticated,
    remote attacker can exploit these, by convincing a user
    to visit a specially crafted website, to execute
    arbitrary code in the context of the current user.
    (CVE-2017-8595, CVE-2017-8598, CVE-2017-8603,
    CVE-2017-8604, CVE-2017-8605, CVE-2017-8619)

  - A remote code execution vulnerability exists in
    Microsoft Edge due to improper handling of objects in
    memory. An unauthenticated, remote attacker can exploit
    this, by convincing a user to visit a specially crafted
    website, to execute arbitrary code in the context of the
    current user. (CVE-2017-8596)

  - A security bypass vulnerability exists in Microsoft Edge
    due to a failure to correctly apply the same-origin
    policy for HTML elements present in other browser
    windows. An unauthenticated, remote attacker can exploit
    this, by convincing a user to follow a link, to cause
    the user to load a malicious website. (CVE-2017-8599)

  - A remote code execution vulnerability exists in
    Microsoft Edge in the Chakra JavaScript engine due to
    improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a specially crafted website,
    to execute arbitrary code in the context of the current
    user. (CVE-2017-8601)

  - A spoofing vulnerability exists in Microsoft browsers
    due to improper parsing of HTTP content. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to click a specially crafted URL, to
    redirect the user to a malicious website.
    (CVE-2017-8602)

  - Multiple remote code execution vulnerabilities exist in
    Microsoft browsers in the JavaScript engines due to
    improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit these, by
    convincing a user to visit a specially crafted website,
    to execute arbitrary code in the context of the current
    user. (CVE-2017-8606, CVE-2017-8607, CVE-2017-8608)

  - A remote code execution vulnerability exists in
    Microsoft browsers in the scripting engine due to
    improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a specially crafted website,
    to execute arbitrary code in the context of the current
    user. (CVE-2017-8609)

  - A spoofing vulnerability exists in Microsoft Edge due to
    improper parsing of HTTP content. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to click a specially crafted URL, to redirect the user
    to a malicious website. (CVE-2017-8611)

  - A remote code execution vulnerability exists in Internet
    Explorer in the VBScript engine due to improper handling
    of objects in memory. An unauthenticated, remote
    attacker can exploit this, by convincing a user to visit
    a specially crafted website, to execute arbitrary code
    in the context of the current user. (CVE-2017-8618)

    * note CVE-2017-8563 introduces a registry setting that
    administrators can use to help make LDAP authentication
    over SSL/TLS more secure, administrators need to create
    a LdapEnforceChannelBinding registry setting on machine
    running AD DS or AD LDS.");
  # https://support.microsoft.com/en-us/help/4025339/windows-10-update-kb4025339
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9415d772");
  # https://support.microsoft.com/en-us/help/4034879/how-to-add-the-ldapenforcechannelbinding-registry-entry
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00f4a98e");
  script_set_attribute(attribute:"solution", value: 
"Apply security update KB4025339 as well as refer to the KB article for additional information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8589");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

## NB: Microsoft 
bulletin = 'MS17-07';
kbs = make_list(4025339);

get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

# Update only applies to Window 10 1607 / Server 2016
if (hotfix_check_sp_range(win10:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_nano() == 1) audit(AUDIT_OS_NOT, "a currently supported OS (Windows Nano Server)");

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = FALSE;

# CVE-2017-8563 applies to both OSes and a
# registry key is required if the target is
# a domain controller.
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Is target a DC?
ret = get_registry_value(
  handle:hklm,
  item:"SYSTEM\CurrentControlSet\Control\ProductOptions\ProductType"
);

my_os_build = get_kb_item("SMB/WindowsVersionBuild");

if (!isnull(ret) && ret == 'LanmanNT' && my_os_build == '14393')
{
  # Target is a DC.
  # Does target have required key for CVE-2017-8563 fix?
  ret = get_registry_value(
    handle:hklm,
    item:"SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding"
  );
  if (isnull(ret) || (ret != '1' && ret != '2'))
  {
      vuln = TRUE;
      reg_key_note =
        '\n  The registry key "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\\LdapEnforceChannelBinding"' +
        '\n  is missing or is not equal to "1" or "2"' +
        '\n';
      hotfix_add_report(reg_key_note, bulletin:bulletin);
  }
}

RegCloseKey(handle:hklm);
close_registry(close:FALSE);


if (
  # Windows 10 1607 / Server 2016
  smb_check_rollup(os:"10", sp:0, os_build:"14393", rollup_date:"07_2017", bulletin:bulletin, rollup_kb_list:kbs) ||
  vuln
)
{
  replace_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
