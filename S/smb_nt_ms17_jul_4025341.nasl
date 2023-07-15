#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101367);
  script_version("1.10");
  script_cvs_date("Date: 2018/08/03 11:35:09");

  script_cve_id(
    "CVE-2017-0170",
    "CVE-2017-8463",
    "CVE-2017-8467",
    "CVE-2017-8486",
    "CVE-2017-8495",
    "CVE-2017-8556",
    "CVE-2017-8557",
    "CVE-2017-8563",
    "CVE-2017-8564",
    "CVE-2017-8565",
    "CVE-2017-8573",
    "CVE-2017-8577",
    "CVE-2017-8578",
    "CVE-2017-8580",
    "CVE-2017-8581",
    "CVE-2017-8582",
    "CVE-2017-8587",
    "CVE-2017-8588",
    "CVE-2017-8589",
    "CVE-2017-8590",
    "CVE-2017-8592"
  );
  script_bugtraq_id(
    99387,
    99389,
    99394,
    99396,
    99398,
    99400,
    99402,
    99409,
    99413,
    99414,
    99416,
    99419,
    99421,
    99423,
    99424,
    99425,
    99427,
    99428,
    99429,
    99431,
    99439
  );
  script_xref(name:"MSKB", value:"4025341");
  script_xref(name:"MSFT", value:"MS17-4025341");
  script_xref(name:"MSKB", value:"4025337");
  script_xref(name:"MSFT", value:"MS17-4025337");

  script_name(english:"Windows 7 and Windows Server 2008 R2 July 2017 Security Updates");
  script_summary(english:"Checks for rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4025337
or cumulative update 4025341. It is, therefore, affected by
multiple vulnerabilities :

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

  - An elevation of privilege vulnerability exists in the
    Microsoft Graphics component due to improper handling
    of objects in memory. A local attacker can exploit this,
    via a specially crafted application, to run arbitrary
    code in kernel mode. (CVE-2017-8467)

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

  - An elevation of privilege vulnerability exists in the
    Microsoft Graphics component due to improper handling
    of objects in memory. A local attacker can exploit this,
    via a specially crafted application, to run arbitrary
    code in kernel mode. (CVE-2017-8556)

  - An information disclosure vulnerability exists in the
    Windows System Information Console due to improper
    parsing of XML input that contains a reference to an
    external entity. An unauthenticated, remote attacker
    can exploit this, by convincing a user to open a
    specially crafted file, to disclose arbitrary files via
    an XML external entity (XXE) declaration.
    (CVE-2017-8557)

  - An elevation of privilege vulnerability exists in
    Windows due to Kerberos falling back to NT LAN Manager
    (NTLM) Authentication Protocol as the default
    authentication protocol. An authenticated, remote
    attacker can exploit this, via an application that
    sends specially crafted traffic to a domain controller,
    to run processes in an elevated context. (CVE-2017-8563)

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

  - An elevation of privilege vulnerability exists in the
    Microsoft Graphics component due to improper handling
    of objects in memory. A local attacker can exploit this,
    via a specially crafted application, to run arbitrary
    code in kernel mode. (CVE-2017-8573)

  - An elevation of privilege vulnerability exists in the
    Microsoft Graphics Component due to improper handling
    of objects in memory. A local attacker can exploit this,
    via a specially crafted application, to run arbitrary
    code in kernel mode. (CVE-2017-8577)

  - An elevation of privilege vulnerability exists in the
    Microsoft Graphics component due to improper handling
    of objects in memory. A local attacker can exploit this,
    via a specially crafted application, to run arbitrary
    code in kernel mode. (CVE-2017-8578)

  - An elevation of privilege vulnerability exists in the
    Microsoft Graphics Component due to improper handling
    of objects in memory. A local attacker can exploit this,
    via a specially crafted application, to run arbitrary
    code in kernel mode. (CVE-2017-8580)

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

  - A denial of service vulnerability exists in Windows
    Explorer that is triggered when Explorer attempts to
    open a non-existent file. An unauthenticated, remote
    attacker can exploit this, by convincing a user to visit
    a specially crafted website, to cause a user's system to
    stop responding. (CVE-2017-8587)

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
    to bypass CORS redirect restrictions. (CVE-2017-8592)");
  # https://support.microsoft.com/en-us/help/4025337/windows-7-update-kb4025337
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d2f3807");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB4025337 or Cumulative update KB4025341.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_family(english:"Windows : Microsoft Bulletins");

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

bulletin = 'MS17-07';
kbs = make_list("4025341", "4025337");
vuln = FALSE;

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

# KB only applies to Window 7 / 2008 R2, SP1
if (hotfix_check_sp_range(win7:'1') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

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

if (!isnull(ret) && ret == 'LanmanNT')
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
        '\n  The registry key "SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\\LdapEnforceChannelBinding"' +
        '\n  is missing or is not equal to "1" or "2"' +
        '\n';
      hotfix_add_report(reg_key_note, bulletin:bulletin);
  }
}

RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if (
  # Windows 7 / 2008 R2
  smb_check_rollup(os:"6.1", sp:1, rollup_date:"07_2017", bulletin:bulletin, rollup_kb_list:[4025341, 4025337])
)
  vuln = TRUE;

if (vuln)
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
