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
  script_id(131926);
  script_version("1.7");
  script_cvs_date("Date: 2020/01/28");

  script_cve_id(
    "CVE-2019-1453",
    "CVE-2019-1465",
    "CVE-2019-1466",
    "CVE-2019-1467",
    "CVE-2019-1468",
    "CVE-2019-1469",
    "CVE-2019-1470",
    "CVE-2019-1471",
    "CVE-2019-1472",
    "CVE-2019-1474",
    "CVE-2019-1476",
    "CVE-2019-1483",
    "CVE-2019-1484",
    "CVE-2019-1485",
    "CVE-2019-1488"
  );
  script_xref(name:"MSKB", value:"4530684");
  script_xref(name:"MSFT", value:"MS19-4530684");

  script_name(english:"KB4530684: Windows 10 Version 1903 and Windows 10 Version 1909 December 2019 Security Update");
  script_summary(english:"Checks for rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4530684.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists when
    Windows Hyper-V on a host server fails to properly
    validate input from an authenticated user on a guest
    operating system.  (CVE-2019-1471)

  - A remote code execution vulnerability exists when
    Microsoft Windows OLE fails to properly validate user
    input. An attacker could exploit the vulnerability to
    execute malicious code.  (CVE-2019-1484)

  - A denial of service vulnerability exists in Remote
    Desktop Protocol (RDP) when an attacker connects to the
    target system using RDP and sends specially crafted
    requests. An attacker who successfully exploited this
    vulnerability could cause the RDP service on the target
    system to stop responding.  (CVE-2019-1453)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2019-1472, CVE-2019-1474)

  - An elevation of privilege vulnerability exists when the
    Windows AppX Deployment Server improperly handles
    junctions.  (CVE-2019-1483)

  - A remote code execution vulnerability exists when the
    Windows font library improperly handles specially
    crafted embedded fonts. An attacker who successfully
    exploited this vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2019-1468)

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
    in memory. (CVE-2019-1465, CVE-2019-1466, CVE-2019-1467)

  - An information disclosure vulnerability exists when the
    win32k component improperly provides kernel information.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2019-1469)

  - An elevation of privilege vulnerability exists when
    Windows AppX Deployment Service (AppXSVC) improperly
    handles hard links. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context. An attacker could then install
    programs; view, change or delete data.  (CVE-2019-1476)

  - An information disclosure vulnerability exists when
    Windows Hyper-V on a host operating system fails to
    properly validate input from an authenticated user on a
    guest operating system.  (CVE-2019-1470)

  - A remote code execution vulnerability exists in the way
    that the VBScript engine handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2019-1485)

  - A security feature bypass vulnerability exists when
    Microsoft Defender improperly handles specific buffers.
    An attacker could exploit the vulnerability to trigger
    warnings and false positives when no threat is present.
    (CVE-2019-1488)");
  # https://support.microsoft.com/en-us/help/4530684/windows-10-update-kb4530684
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f732fcf");
  script_set_attribute(attribute:"solution", value:
"Apply Cumulative Update KB4530684.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1468");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS19-12";
kbs = make_list('4530684');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"18362",
                   rollup_date:"12_2019",
                   bulletin:bulletin,
                   rollup_kb_list:[4530684])
  ||
  smb_check_rollup(os:"10",
                 sp:0,
                 os_build:"18363",
                 rollup_date:"12_2019",
                 bulletin:bulletin,
                 rollup_kb_list:[4530684])
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
