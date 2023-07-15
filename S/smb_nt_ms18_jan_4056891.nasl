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
  script_id(105549);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/18");

  script_cve_id(
    "CVE-2017-5715",
    "CVE-2017-5753",
    "CVE-2017-5754",
    "CVE-2018-0743",
    "CVE-2018-0744",
    "CVE-2018-0745",
    "CVE-2018-0746",
    "CVE-2018-0747",
    "CVE-2018-0748",
    "CVE-2018-0749",
    "CVE-2018-0751",
    "CVE-2018-0752",
    "CVE-2018-0753",
    "CVE-2018-0754",
    "CVE-2018-0758",
    "CVE-2018-0762",
    "CVE-2018-0766",
    "CVE-2018-0767",
    "CVE-2018-0769",
    "CVE-2018-0770",
    "CVE-2018-0772",
    "CVE-2018-0776",
    "CVE-2018-0777",
    "CVE-2018-0780",
    "CVE-2018-0781",
    "CVE-2018-0803"
  );
  script_bugtraq_id(102378);
  script_xref(name:"MSKB", value:"4056891");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");
  script_xref(name:"MSFT", value:"MS18-4056891");
  script_xref(name:"MSKB", value:"4057144");
  script_xref(name:"MSFT", value:"MS18-4057144");

  script_name(english:"KB4056891: Windows 10 Version 1703 January 2018 Security Update (Meltdown)(Spectre)");
  script_summary(english:"Checks for rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4056891
or 4057144. It is, therefore, affected by multiple 
vulnerabilities :

  - An vulnerability exists within microprocessors utilizing 
    speculative execution and indirect branch prediction, 
    which may allow an attacker with local user access to 
    disclose information via a side-channel analysis.
    (CVE-2017-5715, CVE-2017-5753, CVE-2017-5754)

  - An elevation of privilege vulnerability exists when the
    Windows kernel fails to properly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could run arbitrary code in kernel mode.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights.  (CVE-2018-0744)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Microsoft Edge. The vulnerability could corrupt memory
    in such a way that an attacker could execute arbitrary
    code in the context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2018-0758,
    CVE-2018-0769, CVE-2018-0770, CVE-2018-0776,
    CVE-2018-0777, CVE-2018-0781)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Kernel API enforces permissions. An
    attacker who successfully exploited the vulnerability
    could impersonate processes, interject cross-process
    communication, or interrupt system functionality.
    (CVE-2018-0748, CVE-2018-0751, CVE-2018-0752)

  - An elevation of privilege vulnerability exists when
    Microsoft Edge does not properly enforce cross-domain
    policies, which could allow an attacker to access
    information from one domain and inject it into another
    domain.  (CVE-2018-0803)

  - An information disclosure vulnerability exists in
    Windows Adobe Type Manager Font Driver (ATMFD.dll) when
    it fails to properly handle objects in memory. An
    attacker who successfully exploited this vulnerability
    could potentially read data that was not intended to be
    disclosed. Note that this vulnerability would not allow
    an attacker to execute code or to elevate their user
    rights directly, but it could be used to obtain
    information that could be used to try to further
    compromise the affected system.  (CVE-2018-0754)

  - A remote code execution vulnerability exists in the way
    the scripting engine handles objects in memory in
    Microsoft browsers. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2018-0762, CVE-2018-0772)

  - An information disclosure vulnerability exists when
    Microsoft Edge PDF Reader improperly handles objects in
    memory. An attacker who successfully exploited the
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2018-0766)

  - An information disclosure vulnerability exists when the
    scripting engine does not properly handle objects in
    memory in Microsoft Edge. An attacker who successfully
    exploited the vulnerability could obtain information to
    further compromise the users system.  (CVE-2018-0767,
    CVE-2018-0780)

  - An elevation of privilege vulnerability exists in the
    Microsoft Server Message Block (SMB) Server when an
    attacker with valid credentials attempts to open a
    specially crafted file over the SMB protocol on the same
    machine. An attacker who successfully exploited this
    vulnerability could bypass certain security checks in
    the operating system.  (CVE-2018-0749)

  - A denial of service vulnerability exists in the way that
    Windows handles objects in memory. An attacker who
    successfully exploited the vulnerability could cause a
    target system to stop responding. Note that the denial
    of service condition would not allow an attacker to
    execute code or to elevate user privileges. However, the
    denial of service condition could prevent authorized
    users from using system resources. The security update
    addresses the vulnerability by correcting how Windows
    handles objects in memory. (CVE-2018-0753)

  - An information disclosure vulnerability exists in the
    Windows kernel that could allow an attacker to retrieve
    information that could lead to a Kernel Address Space
    Layout Randomization (ASLR) bypass. An attacker who
    successfully exploited the vulnerability could retrieve
    the memory address of a kernel object.  (CVE-2018-0745,
    CVE-2018-0746, CVE-2018-0747)

  - An elevation of privilege vulnerability exists due to an
    integer overflow in Windows Subsystem for Linux. An
    attacker who successfully exploited the vulnerability
    could execute code with elevated permissions.
    (CVE-2018-0743)");
  # https://support.microsoft.com/en-us/help/4056891/windows-10-update-kb4056891
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc98fbd6");
  # https://support.microsoft.com/en-ca/help/4057144/windows-10-update-kb4057144
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d90c1a83");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4072699/windows-security-updates-and-antivirus-software");  
  script_set_attribute(attribute:"solution", value:
  "Apply Cumulative Update KB4056891 or KB4057144.

Notes: 

  - Due to a compatibility issue with some antivirus
    software products, it may not be possible to apply 
    the required updates.
    See Microsoft KB article 4072699 for more information.

  - KB4057144 Addresses an issue with KB4056891 where some 
    customers on a small subset of older AMD processors get 
    into an unbootable state.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/04");

  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2020 Tenable Network Security, Inc.");

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

bulletin = "MS18-01";
kbs = make_list('4056891','4057144');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"15063",
                   rollup_date:"01_2018",
                   bulletin:bulletin,
                   rollup_kb_list:[4056891,4057144])
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
