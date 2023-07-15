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
  script_id(108967);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/18");

  script_cve_id(
    "CVE-2018-0870",
    "CVE-2018-0887",
    "CVE-2018-0890",
    "CVE-2018-0892",
    "CVE-2018-0956",
    "CVE-2018-0957",
    "CVE-2018-0960",
    "CVE-2018-0963",
    "CVE-2018-0966",
    "CVE-2018-0967",
    "CVE-2018-0968",
    "CVE-2018-0969",
    "CVE-2018-0970",
    "CVE-2018-0971",
    "CVE-2018-0972",
    "CVE-2018-0973",
    "CVE-2018-0974",
    "CVE-2018-0975",
    "CVE-2018-0976",
    "CVE-2018-0979",
    "CVE-2018-0980",
    "CVE-2018-0981",
    "CVE-2018-0987",
    "CVE-2018-0988",
    "CVE-2018-0989",
    "CVE-2018-0990",
    "CVE-2018-0991",
    "CVE-2018-0993",
    "CVE-2018-0994",
    "CVE-2018-0995",
    "CVE-2018-0996",
    "CVE-2018-0997",
    "CVE-2018-0998",
    "CVE-2018-1000",
    "CVE-2018-1001",
    "CVE-2018-1003",
    "CVE-2018-1004",
    "CVE-2018-1008",
    "CVE-2018-1009",
    "CVE-2018-1010",
    "CVE-2018-1012",
    "CVE-2018-1013",
    "CVE-2018-1015",
    "CVE-2018-1016",
    "CVE-2018-1018",
    "CVE-2018-1020",
    "CVE-2018-1023",
    "CVE-2018-8116",
    "CVE-2018-8142"
  );
  script_xref(name:"MSKB", value:"4093119");
  script_xref(name:"MSFT", value:"MS18-4093119");

  script_name(english:"KB4093119: Windows 10 Version 1607 and Windows Server 2016 April 2018 Security Update");
  script_summary(english:"Checks for rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4093119.
It is, therefore, affected by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists when
    Windows improperly handles objects in memory and
    incorrectly maps kernel memory.  (CVE-2018-1009)

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
    (CVE-2018-0966)

  - A denial of service vulnerability exists in the way that
    Windows SNMP Service handles malformed SNMP traps. An
    attacker who successfully exploited the vulnerability
    could cause a target system to stop responding. Note
    that the denial of service condition would not allow an
    attacker to execute code or to elevate user privileges.
    However, the denial of service condition could prevent
    authorized users from using system resources. The
    security update addresses the vulnerability by
    correcting how Windows SNMP Service processes SNMP
    traps. (CVE-2018-0967)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2018-0960)

  - An elevation of privilege vulnerability exists in
    Windows Adobe Type Manager Font Driver (ATMFD.dll) when
    it fails to properly handle objects in memory. An
    attacker who successfully exploited this vulnerability
    could execute arbitrary code and take control of an
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2018-1008)

  - An information disclosure vulnerability exists when
    Microsoft Edge improperly handles objects in memory. An
    attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2018-0892)

  - An information disclosure vulnerability exists when
    Windows Hyper-V on a host operating system fails to
    properly validate input from an authenticated user on a
    guest operating system.  (CVE-2018-0957)

  - An information disclosure vulnerability exists when the
    scripting engine does not properly handle objects in
    memory in Internet Explorer. An attacker who
    successfully exploited the vulnerability could obtain
    information to further compromise the users system.
    (CVE-2018-0987)

  - A buffer overflow vulnerability exists in the Microsoft
    JET Database Engine that could allow remote code
    execution on an affected system. An attacker who
    successfully exploited this vulnerability could take
    control of an affected system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights. Users whose
    accounts are configured to have fewer user rights on the
    system could be less impacted than users who operate
    with administrative user rights.  (CVE-2018-1003)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Kernel handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2018-0963)

  - A denial of service vulnerability exists in Remote
    Desktop Protocol (RDP) when an attacker connects to the
    target system using RDP and sends specially crafted
    requests. An attacker who successfully exploited this
    vulnerability could cause the RDP service on the target
    system to stop responding.  (CVE-2018-0976)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2018-0988, CVE-2018-0996, CVE-2018-1001)

  - A security feature bypass vulnerability exists when
    Active Directory incorrectly applies Network Isolation
    settings.  (CVE-2018-0890)

  - A remote code execution vulnerability exists when the
    Windows font library improperly handles specially
    crafted embedded fonts. An attacker who successfully
    exploited the vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2018-1010,
    CVE-2018-1012, CVE-2018-1013, CVE-2018-1015,
    CVE-2018-1016)

  - An information disclosure vulnerability exists in the
    way that the scripting engine handles objects in memory
    in Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could provide an
    attacker with information to further compromise the
    user's computer or data.  (CVE-2018-0981, CVE-2018-0989,
    CVE-2018-1000)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2018-0870,
    CVE-2018-0991, CVE-2018-0997, CVE-2018-1018,
    CVE-2018-1020)

  - An information disclosure vulnerability exists when
    Microsoft Edge PDF Reader improperly handles objects in
    memory. An attacker who successfully exploited the
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2018-0998)

  - A remote code execution vulnerability exists in the way
    that Microsoft browsers access objects in memory. The
    vulnerability could corrupt memory in a way that could
    allow an attacker to execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2018-1023)

  - An information disclosure vulnerability exists in the
    Windows kernel that could allow an attacker to retrieve
    information that could lead to a Kernel Address Space
    Layout Randomization (ASLR) bypass. An attacker who
    successfully exploited the vulnerability could retrieve
    the memory address of a kernel object.  (CVE-2018-0968,
    CVE-2018-0969, CVE-2018-0970, CVE-2018-0971,
    CVE-2018-0972, CVE-2018-0973, CVE-2018-0974,
    CVE-2018-0975)

  - A denial of service vulnerability exists in the way that
    Windows handles objects in memory. An attacker who
    successfully exploited the vulnerability could cause a
    target system to stop responding. Note that the denial
    of service condition would not allow an attacker to
    execute code or to elevate user privileges. However, the
    denial of service condition could prevent authorized
    users from using system resources. The security update
    addresses the vulnerability by correcting how Windows
    handles objects in memory. (CVE-2018-8116)

  - A remote code execution vulnerability exists in the way
    that the VBScript engine handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2018-1004)

  - A remote code execution vulnerability exists in the way
    that the Chakra scripting engine handles objects in
    memory in Microsoft Edge. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. An attacker who successfully exploited the
    vulnerability could gain the same user rights as the
    current user.  (CVE-2018-0979, CVE-2018-0980,
    CVE-2018-0990, CVE-2018-0993, CVE-2018-0994,
    CVE-2018-0995)

  - A denial of service vulnerability exists in the HTTP 2.0
    protocol stack (HTTP.sys) when HTTP.sys improperly
    parses specially crafted HTTP 2.0 requests. An attacker
    who successfully exploited the vulnerability could
    create a denial of service condition, causing the target
    system to become unresponsive.  (CVE-2018-0956)

  - An information disclosure vulnerability exists when the
    Windows kernel fails to properly initialize a memory
    address. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2018-0887)");
  # https://support.microsoft.com/en-us/help/4093119/windows-10-update-kb4093119
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2553c1b5");
  script_set_attribute(attribute:"solution", value:
"Apply Cumulative Update KB4093119.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1016");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS18-04";
kbs = make_list('4093119');

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
                   rollup_date:"04_2018",
                   bulletin:bulletin,
                   rollup_kb_list:[4093119])
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
