#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117413);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/29");

  script_cve_id(
    "CVE-2018-0965",
    "CVE-2018-8271",
    "CVE-2018-8315",
    "CVE-2018-8332",
    "CVE-2018-8335",
    "CVE-2018-8354",
    "CVE-2018-8367",
    "CVE-2018-8392",
    "CVE-2018-8393",
    "CVE-2018-8410",
    "CVE-2018-8419",
    "CVE-2018-8420",
    "CVE-2018-8421",
    "CVE-2018-8424",
    "CVE-2018-8425",
    "CVE-2018-8433",
    "CVE-2018-8434",
    "CVE-2018-8435",
    "CVE-2018-8438",
    "CVE-2018-8439",
    "CVE-2018-8440",
    "CVE-2018-8442",
    "CVE-2018-8443",
    "CVE-2018-8446",
    "CVE-2018-8447",
    "CVE-2018-8449",
    "CVE-2018-8452",
    "CVE-2018-8455",
    "CVE-2018-8457",
    "CVE-2018-8462",
    "CVE-2018-8464",
    "CVE-2018-8465",
    "CVE-2018-8466",
    "CVE-2018-8467",
    "CVE-2018-8468",
    "CVE-2018-8469",
    "CVE-2018-8470",
    "CVE-2018-8475"
  );
  script_xref(name:"MSKB", value:"4457131");
  script_xref(name:"MSFT", value:"MS18-4457131");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/18");

  script_name(english:"KB4457131: Windows 10 Version 1607 and Windows Server 2016 September 2018 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4457131.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in the way
    the scripting engine handles objects in memory in
    Microsoft browsers. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2018-8457)

  - An information disclosure vulnerability exists when the
    Windows GDI component improperly discloses the contents
    of its memory. An attacker who successfully exploited
    the vulnerability could obtain information to further
    compromise the users system. There are multiple ways an
    attacker could exploit the vulnerability, such as by
    convincing a user to open a specially crafted document,
    or by convincing a user to visit an untrusted webpage.
    The security update addresses the vulnerability by
    correcting how the Windows GDI component handles objects
    in memory. (CVE-2018-8424)

  - A remote code execution vulnerability exists when
    Windows Hyper-V on a host server fails to properly
    validate input from an authenticated user on a guest
    operating system.  (CVE-2018-0965, CVE-2018-8439)

  - A remote code execution vulnerability exists when
    Windows does not properly handle specially crafted image
    files. An attacker who successfully exploited the
    vulnerability could execute arbitrary code.
    (CVE-2018-8475)

  - An elevation of privilege vulnerability exists when
    Windows improperly handles calls to Advanced Local
    Procedure Call (ALPC). An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    the security context of the local system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2018-8440)

  - An elevation of privilege vulnerability exists in
    Microsoft Edge that could allow an attacker to escape
    from the AppContainer sandbox in the browser. An
    attacker who successfully exploited this vulnerability
    could gain elevated privileges and break out of the Edge
    AppContainer sandbox. The vulnerability by itself does
    not allow arbitrary code to run. However, this
    vulnerability could be used in conjunction with one or
    more vulnerabilities (for example a remote code
    execution vulnerability and another elevation of
    privilege vulnerability) to take advantage of the
    elevated privileges when running. The security update
    addresses the vulnerability by modifying how Microsoft
    Edge handles sandboxing. (CVE-2018-8469)

  - An elevation of privilege vulnerability exists in
    Windows that allows a sandbox escape. An attacker who
    successfully exploited the vulnerability could use the
    sandbox escape to elevate privileges on an affected
    system. This vulnerability by itself does not allow
    arbitrary code execution. However, the vulnerability
    could allow arbitrary code to run if an attacker uses it
    in combination with another vulnerability, such as a
    remote code execution vulnerability or another elevation
    of privilege vulnerability, that can leverage the
    elevated privileges when code execution is attempted.
    The security update addresses the vulnerability by
    correcting how Windows parses files. (CVE-2018-8468)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system. An authenticated attacker could exploit this
    vulnerability by running a specially crafted
    application. The update addresses the vulnerability by
    correcting how the Windows kernel handles objects in
    memory. (CVE-2018-8442, CVE-2018-8443)

  - An information disclosure vulnerability exists when the
    Windows kernel fails to properly initialize a memory
    address. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2018-8419)

  - An elevation of privilege vulnerability exists when the
    Windows Kernel API improperly handles registry objects
    in memory. An attacker who successfully exploited the
    vulnerability could gain elevated privileges on a
    targeted system. A locally authenticated attacker could
    exploit this vulnerability by running a specially
    crafted application. The security update addresses the
    vulnerability by helping to ensure that the Windows
    Kernel API properly handles objects in memory.
    (CVE-2018-8410)

  - An elevation of privilege vulnerability exists when the
    DirectX Graphics Kernel (DXGKRNL) driver improperly
    handles objects in memory. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context.  (CVE-2018-8462)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2018-8446)

  - A remote code execution vulnerability exists when the
    Microsoft XML Core Services MSXML parser processes user
    input. An attacker who successfully exploited the
    vulnerability could run malicious code remotely to take
    control of the users system.  (CVE-2018-8420)

  - A denial of service vulnerability exists when Microsoft
    Hyper-V Network Switch on a host server fails to
    properly validate input from a privileged user on a
    guest operating system. An attacker who successfully
    exploited the vulnerability could cause the host server
    to crash.  (CVE-2018-8438)

  - An information disclosure vulnerability exists when
    Windows Hyper-V on a host operating system fails to
    properly validate input from an authenticated user on a
    guest operating system.  (CVE-2018-8434)

  - A remote code execution vulnerability exists when the
    Windows font library improperly handles specially
    crafted embedded fonts. An attacker who successfully
    exploited this vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2018-8332)

  - An information disclosure vulnerability exists when the
    browser scripting engine improperly handle object types.
    An attacker who has successfully exploited this
    vulnerability might be able to read privileged data
    across trust boundaries. In browsing scenarios, an
    attacker could convince a user to visit a malicious site
    and leverage the vulnerability to obtain privileged
    information from the browser process, such as sensitive
    data from other opened tabs. An attacker could also
    inject malicious code into advertising networks used by
    trusted sites or embed malicious code on a compromised,
    but trusted, site. The security update addresses the
    vulnerability by correcting how the browser scripting
    engine handles object types. (CVE-2018-8315)

  - A buffer overflow vulnerability exists in the Microsoft
    JET Database Engine that could allow remote code
    execution on an affected system. An attacker who
    successfully exploited this vulnerability could take
    control of an affected system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights. Users whose
    accounts are configured to have fewer user rights on the
    system could be less impacted than users who operate
    with administrative user rights.  (CVE-2018-8392,
    CVE-2018-8393)

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
    (CVE-2018-8335)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Kernel handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2018-8455)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2018-8447)

  - An information disclosure vulnerability exists in
    Windows when the Windows bowser.sys kernel-mode driver
    fails to properly handle objects in memory. An attacker
    who successfully exploited the vulnerability could
    potentially disclose contents of System memory.
    (CVE-2018-8271)

  - An remote code execution vulnerability exists when
    Microsoft Edge PDF Reader improperly handles objects in
    memory. The vulnerability could corrupt memory in such a
    way that enables an attacker to execute arbitrary code
    in the context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user. If the current
    user is logged on with administrative user rights, an
    attacker could take control of an affected system. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts with full user
    rights.  (CVE-2018-8464)

  - A remote code execution vulnerability exists when
    Microsoft .NET Framework processes input. An attacker
    who successfully exploited this vulnerability could take
    control of an affected system.  (CVE-2018-8421)

  - A remote code execution vulnerability exists in the way
    that the Chakra scripting engine handles objects in
    memory in Microsoft Edge. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. An attacker who successfully exploited the
    vulnerability could gain the same user rights as the
    current user.  (CVE-2018-8367, CVE-2018-8465,
    CVE-2018-8466, CVE-2018-8467)

  - An information disclosure vulnerability exists when the
    scripting engine does not properly handle objects in
    memory in Microsoft browsers. An attacker who
    successfully exploited the vulnerability could obtain
    information to further compromise the users system.
    (CVE-2018-8452)

  - A security feature bypass exists when Device Guard
    incorrectly validates an untrusted file. An attacker who
    successfully exploited this vulnerability could make an
    unsigned file appear to be signed. Because Device Guard
    relies on the signature to determine the file is non-
    malicious, Device Guard could then allow a malicious
    file to execute. In an attack scenario, an attacker
    could make an untrusted file appear to be a trusted
    file. The update addresses the vulnerability by
    correcting how Device Guard handles untrusted files.
    (CVE-2018-8449)

  - An information disclosure vulnerability exists when the
    Windows Graphics component improperly handles objects in
    memory. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system. An authenticated attacker
    could exploit this vulnerability by running a specially
    crafted application. The update addresses the
    vulnerability by correcting how the Windows Graphics
    Component handles objects in memory. (CVE-2018-8433)

  - A security feature bypass vulnerability exists when
    Windows Hyper-V BIOS loader fails to provide a high-
    entropy source.  (CVE-2018-8435)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Microsoft Edge. The vulnerability could corrupt memory
    in such a way that an attacker could execute arbitrary
    code in the context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2018-8354)

  - A security feature bypass vulnerability exists in
    Internet Explorer due to how scripts are handled that
    allows a universal cross-site scripting (UXSS)
    condition. An attacker could use the UXSS vulnerability
    to access any session belonging to web pages currently
    opened (or cached) by the browser at the time the attack
    is triggered.  (CVE-2018-8470)

  - A spoofing vulnerability exists when Microsoft Edge
    improperly handles specific HTML content. An attacker
    who successfully exploited this vulnerability could
    trick a user into believing that the user was on a
    legitimate website. The specially crafted website could
    either spoof content or serve as a pivot to chain an
    attack with other vulnerabilities in web services.
    (CVE-2018-8425)");
  # https://support.microsoft.com/en-us/help/4457131/windows-10-update-kb4457131
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db9cdb46");
  script_set_attribute(attribute:"solution", value:
"Apply Cumulative Update KB4457131.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8421");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows ALPC Task Scheduler Local Privilege Elevation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/11");

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

bulletin = "MS18-09";
kbs = make_list('4457131');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"14393",
                   rollup_date:"09_2018",
                   bulletin:bulletin,
                   rollup_kb_list:[4457131])
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
