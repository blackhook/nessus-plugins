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
  script_id(132865);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-0601",
    "CVE-2020-0605",
    "CVE-2020-0606",
    "CVE-2020-0607",
    "CVE-2020-0608",
    "CVE-2020-0611",
    "CVE-2020-0613",
    "CVE-2020-0614",
    "CVE-2020-0615",
    "CVE-2020-0617",
    "CVE-2020-0620",
    "CVE-2020-0622",
    "CVE-2020-0623",
    "CVE-2020-0625",
    "CVE-2020-0626",
    "CVE-2020-0627",
    "CVE-2020-0628",
    "CVE-2020-0629",
    "CVE-2020-0630",
    "CVE-2020-0631",
    "CVE-2020-0632",
    "CVE-2020-0634",
    "CVE-2020-0635",
    "CVE-2020-0639",
    "CVE-2020-0640",
    "CVE-2020-0641",
    "CVE-2020-0642",
    "CVE-2020-0643",
    "CVE-2020-0644",
    "CVE-2020-0646"
  );
  script_xref(name:"IAVA", value:"2020-A-0010");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2020/01/29");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"MSKB", value:"4534306");
  script_xref(name:"MSFT", value:"MS20-4534306");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");
  script_xref(name:"CEA-ID", value:"CEA-2020-0009");

  script_name(english:"KB4534306: Windows 10 January 2020 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4534306.
It is, therefore, affected by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists in the
    way that the Windows Search Indexer handles objects in
    memory. An attacker who successfully exploited the
    vulnerability could execute code with elevated
    permissions.  (CVE-2020-0613, CVE-2020-0614,
    CVE-2020-0623, CVE-2020-0625, CVE-2020-0626,
    CVE-2020-0627, CVE-2020-0628, CVE-2020-0629,
    CVE-2020-0630, CVE-2020-0631, CVE-2020-0632)

  - An information disclosure vulnerability exists in the
    Windows Common Log File System (CLFS) driver when it
    fails to properly handle objects in memory. An attacker
    who successfully exploited this vulnerability could
    potentially read data that was not intended to be
    disclosed. Note that this vulnerability would not allow
    an attacker to execute code or to elevate their user
    rights directly, but it could be used to obtain
    information that could be used to try to further
    compromise the affected system.  (CVE-2020-0615,
    CVE-2020-0639)

  - An elevation of privilege vulnerability exists in
    Windows when the Win32k component fails to properly
    handle objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2020-0642)

  - A remote code execution vulnerability exists in .NET
    software when the software fails to check the source
    markup of a file. An attacker who successfully exploited
    the vulnerability could run arbitrary code in the
    context of the current user. If the current user is
    logged on with administrative user rights, an attacker
    could take control of the affected system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2020-0605, CVE-2020-0606)

  - A denial of service vulnerability exists when Microsoft
    Hyper-V Virtual PCI on a host server fails to properly
    validate input from a privileged user on a guest
    operating system.  (CVE-2020-0617)

  - An elevation of privilege vulnerability exists in
    Microsoft Windows when Windows fails to properly handle
    certain symbolic links. An attacker who successfully
    exploited this vulnerability could potentially set
    certain items to run at a higher level and thereby
    elevate permissions.  (CVE-2020-0635)

  - An information disclosure vulnerability exists in the
    way that the Windows Graphics Device Interface Plus
    (GDI+) handles objects in memory, allowing an attacker
    to retrieve information from a targeted system. By
    itself, the information disclosure does not allow
    arbitrary code execution; however, it could allow
    arbitrary code to be run if the attacker uses it in
    combination with another vulnerability.  (CVE-2020-0643)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2020-0640)

  - An information disclosure vulnerability exists when the
    Microsoft Windows Graphics Component improperly handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could obtain information to
    further compromise the users system.  (CVE-2020-0622)

  - An information disclosure vulnerability exists when the
    win32k component improperly provides kernel information.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2020-0608)

  - An elevation of privilege vulnerability exists when
    Microsoft Cryptographic Services improperly handles
    files. An attacker could exploit the vulnerability to
    overwrite or modify a protected file leading to a
    privilege escalation.  (CVE-2020-0620)

  - An elevation of privilege vulnerability exists when the
    Windows Common Log File System (CLFS) driver improperly
    handles objects in memory. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context.  (CVE-2020-0634)

  - An elevation of privilege vulnerability exists in
    Windows Media Service that allows file creation in
    arbitrary locations.  (CVE-2020-0641)

  - An information disclosure vulnerability exists in the
    way that Microsoft Graphics Components handle objects in
    memory. An attacker who successfully exploited the
    vulnerability could obtain information that could be
    useful for further exploitation.  (CVE-2020-0607)

  - A remote code execution vulnerability exists when the
    Microsoft .NET Framework fails to validate input
    properly. An attacker who successfully exploited this
    vulnerability could take control of an affected system.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights. Users whose accounts are configured to have
    fewer user rights on the system could be less impacted
    than users who operate with administrative user rights.
    (CVE-2020-0646)

  - A remote code execution vulnerability exists in the
    Windows Remote Desktop Client when a user connects to a
    malicious server. An attacker who successfully exploited
    this vulnerability could execute arbitrary code on the
    computer of the connecting client. An attacker could
    then install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2020-0611)

  - An elevation of privilege vulnerability exists when
    Microsoft Windows implements predictable memory section
    names. An attacker who successfully exploited this
    vulnerability could run arbitrary code as system. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts with full user
    rights.  (CVE-2020-0644)

  - A spoofing vulnerability exists in the way Windows
    CryptoAPI (Crypt32.dll) validates Elliptic Curve
    Cryptography (ECC) certificates. An attacker could
    exploit the vulnerability by using a spoofed code-
    signing certificate to sign a malicious executable,
    making it appear the file was from a trusted, legitimate
    source. The user would have no way of knowing the file
    was malicious, because the digital signature would
    appear to be from a trusted provider. A successful
    exploit could also allow the attacker to conduct man-in-
    the-middle attacks and decrypt confidential information
    on user connections to the affected software. The
    security update addresses the vulnerability by ensuring
    that Windows CryptoAPI completely validates ECC
    certificates. (CVE-2020-0601)");
  # https://support.microsoft.com/en-us/help/4534306/windows-10-update-kb4534306
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fd98f0c");
  script_set_attribute(attribute:"solution", value:
"Apply Cumulative Update KB4534306.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0646");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SharePoint Workflows XOML Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/14");

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

bulletin = "MS20-01";
kbs = make_list('4534306');

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
                   rollup_date:"01_2020",
                   bulletin:bulletin,
                   rollup_kb_list:[4534306])
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
