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
  script_id(117998);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/24");

  script_cve_id(
    "CVE-2018-8320",
    "CVE-2018-8330",
    "CVE-2018-8333",
    "CVE-2018-8411",
    "CVE-2018-8413",
    "CVE-2018-8423",
    "CVE-2018-8453",
    "CVE-2018-8460",
    "CVE-2018-8472",
    "CVE-2018-8481",
    "CVE-2018-8482",
    "CVE-2018-8484",
    "CVE-2018-8486",
    "CVE-2018-8489",
    "CVE-2018-8490",
    "CVE-2018-8491",
    "CVE-2018-8492",
    "CVE-2018-8493",
    "CVE-2018-8494",
    "CVE-2018-8495",
    "CVE-2018-8497",
    "CVE-2018-8503",
    "CVE-2018-8505",
    "CVE-2018-8506",
    "CVE-2018-8509",
    "CVE-2018-8512",
    "CVE-2018-8530"
  );
  script_bugtraq_id(105477, 105478);
  script_xref(name:"MSKB", value:"4462918");
  script_xref(name:"MSFT", value:"MS18-4462918");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/21");

  script_name(english:"KB4462918: Windows 10 Version 1709 and Windows Server Version 1709 October 2018 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4462918.
It is, therefore, affected by multiple vulnerabilities :

  - A security feature bypass vulnerability exists in DNS
    Global Blocklist feature. An attacker who successfully
    exploited this vulnerability could redirect traffic to
    malicious DNS endpoints. The update addresses the
    vulnerability by updating DNS Server Role record
    additions to not bypass the Global Query Blocklist.
    (CVE-2018-8320)

  - An information disclosure vulnerability exists when the
    Windows TCP/IP stack improperly handles fragmented IP
    packets. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2018-8493)

  - A security feature bypass vulnerability exists when
    Microsoft Edge improperly handles requests of different
    origins. The vulnerability allows Microsoft Edge to
    bypass Same-Origin Policy (SOP) restrictions, and to
    allow requests that should otherwise be ignored. An
    attacker who successfully exploited the vulnerability
    could force the browser to send data that would
    otherwise be restricted.  (CVE-2018-8530)

  - An elevation of privilege vulnerability exists when NTFS
    improperly checks access. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context.  (CVE-2018-8411)

  - A security feature bypass vulnerability exists in Device
    Guard that could allow an attacker to inject malicious
    code into a Windows PowerShell session. An attacker who
    successfully exploited this vulnerability could inject
    code into a trusted PowerShell process to bypass the
    Device Guard Code Integrity policy on the local machine.
    (CVE-2018-8492)

  - An elevation of privilege vulnerability exists when the
    DirectX Graphics Kernel (DXGKRNL) driver improperly
    handles objects in memory. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context.  (CVE-2018-8484)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Kernel handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2018-8497)

  - An information disclosure vulnerability exists in the
    way that the Windows Graphics Device Interface (GDI)
    handles objects in memory, allowing an attacker to
    retrieve information from a targeted system. By itself,
    the information disclosure does not allow arbitrary code
    execution; however, it could allow arbitrary code to be
    run if the attacker uses it in combination with another
    vulnerability.  (CVE-2018-8472)

  - A remote code execution vulnerability exists when
    Microsoft Edge improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that enables an attacker to execute arbitrary code in
    the context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2018-8509)

  - A remote code execution vulnerability exists when
    &quot;Windows Theme API&quot; does not properly
    decompress files. An attacker who successfully exploited
    the vulnerability could run arbitrary code in the
    context of the current user. If the current user is
    logged on with administrative user rights, an attacker
    could take control of the affected system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    Users whose accounts are configured to have fewer user
    rights on the system could be less impacted than users
    who operate with administrative user rights.
    (CVE-2018-8413)

  - An elevation of privilege vulnerability exists in
    Windows when the Win32k component fails to properly
    handle objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2018-8453)

  - A remote code execution vulnerability exists in the way
    that the Chakra scripting engine handles objects in
    memory in Microsoft Edge. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. An attacker who successfully exploited the
    vulnerability could gain the same user rights as the
    current user.  (CVE-2018-8503, CVE-2018-8505)

  - A remote code execution vulnerability exists in the
    Microsoft JET Database Engine. An attacker who
    successfully exploited this vulnerability could take
    control of an affected system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights. Users whose
    accounts are configured to have fewer user rights on the
    system could be less impacted than users who operate
    with administrative user rights.  (CVE-2018-8423)

  - An Information Disclosure vulnerability exists in the
    way that Microsoft Windows Codecs Library handles
    objects in memory. An attacker who successfully
    exploited this vulnerability could obtain information to
    further compromise the users system. Exploitation of the
    vulnerability requires that a program process a
    specially crafted image file. The update addresses the
    vulnerability by correcting how Microsoft Windows Codecs
    Library handles objects in memory. (CVE-2018-8506)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2018-8460,
    CVE-2018-8491)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2018-8330)

  - An information disclosure vulnerability exists when
    DirectX improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system. An authenticated attacker could exploit this
    vulnerability by running a specially crafted
    application. The update addresses the vulnerability by
    correcting how DirectX handles objects in memory.
    (CVE-2018-8486)

  - A security feature bypass vulnerability exists in
    Microsoft Edge when the Edge Content Security Policy
    (CSP) fails to properly validate certain specially
    crafted documents. An attacker who exploited the bypass
    could trick a user into loading a page containing
    malicious content.  (CVE-2018-8512)

  - An Elevation of Privilege vulnerability exists in Filter
    Manager when it improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could execute elevated code and take control of an
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2018-8333)

  - A remote code execution vulnerability exists when the
    Microsoft XML Core Services MSXML parser processes user
    input. An attacker who successfully exploited the
    vulnerability could run malicious code remotely to take
    control of the users system.  (CVE-2018-8494)

  - A remote code execution vulnerability exists when
    Windows Hyper-V on a host server fails to properly
    validate input from an authenticated user on a guest
    operating system.  (CVE-2018-8489, CVE-2018-8490)

  - An information disclosure vulnerability exists when
    Windows Media Player improperly discloses file
    information. Successful exploitation of the
    vulnerability could allow an attacker to determine the
    presence of files on disk.  (CVE-2018-8481,
    CVE-2018-8482)

  - A remote code execution vulnerability exists when
    Windows Shell improperly handles URIs. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2018-8495)");
  # https://support.microsoft.com/en-us/help/4462918/windows-10-update-kb4462918
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb51c9ad");
  script_set_attribute(attribute:"solution", value:
"Apply Cumulative Update KB4462918.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8494");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Windows NtUserSetWindowFNID Win32k User Callback');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS18-10";
kbs = make_list('4462918');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"16299",
                   rollup_date:"10_2018",
                   bulletin:bulletin,
                   rollup_kb_list:[4462918])
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
