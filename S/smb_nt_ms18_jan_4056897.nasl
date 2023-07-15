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
  script_id(105552);
  script_version("1.20");
  script_cvs_date("Date: 2019/12/18");

  script_cve_id(
    "CVE-2017-5715",
    "CVE-2017-5753",
    "CVE-2017-5754",
    "CVE-2018-0741",
    "CVE-2018-0747",
    "CVE-2018-0748",
    "CVE-2018-0749",
    "CVE-2018-0750",
    "CVE-2018-0754",
    "CVE-2018-0762",
    "CVE-2018-0772",
    "CVE-2018-0788"
  );
  script_bugtraq_id(102378);
  script_xref(name:"MSKB", value:"4056897");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");
  script_xref(name:"MSKB", value:"4056894");
  script_xref(name:"MSFT", value:"MS18-4056897");
  script_xref(name:"MSFT", value:"MS18-4056894");

  script_name(english:"KB4056897: Windows 7 and Windows Server 2008 R2 January 2018 Security Update (Meltdown)(Spectre)");
  script_summary(english:"Checks for rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4056897
or cumulative update 4056894. It is, therefore, affected by
multiple vulnerabilities :

  - An vulnerability exists within microprocessors utilizing 
    speculative execution and indirect branch prediction, 
    which may allow an attacker with local user access to 
    disclose information via a side-channel analysis.
    (CVE-2017-5715, CVE-2017-5753, CVE-2017-5754)

  - An elevation of privilege vulnerability exists in
    Windows Adobe Type Manager Font Driver (ATMFD.dll) when
    it fails to properly handle objects in memory. An
    attacker who successfully exploited this vulnerability
    could execute arbitrary code and take control of an
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2018-0788)

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

  - An information disclosure vulnerability exists in the
    way that the Color Management Module (ICM32.dll) handles
    objects in memory. This vulnerability allows an attacker
    to retrieve information to bypass usermode ASLR (Address
    Space Layout Randomization) on a targeted system. By
    itself, the information disclosure does not allow
    arbitrary code execution; however, it could allow
    arbitrary code to be run if the attacker uses it in
    combination with another vulnerability.  (CVE-2018-0741)

  - An information disclosure vulnerability exists in the
    Windows kernel that could allow an attacker to retrieve
    information that could lead to a Kernel Address Space
    Layout Randomization (ASLR) bypass. An attacker who
    successfully exploited the vulnerability could retrieve
    the memory address of a kernel object.  (CVE-2018-0747)

  - An elevation of privilege vulnerability exists in the
    Microsoft Server Message Block (SMB) Server when an
    attacker with valid credentials attempts to open a
    specially crafted file over the SMB protocol on the same
    machine. An attacker who successfully exploited this
    vulnerability could bypass certain security checks in
    the operating system.  (CVE-2018-0749)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Kernel API enforces permissions. An
    attacker who successfully exploited the vulnerability
    could impersonate processes, interject cross-process
    communication, or interrupt system functionality.
    (CVE-2018-0748)

  - A Win32k information disclosure vulnerability exists
    when the Windows GDI component improperly discloses
    kernel memory addresses. An attacker who successfully
    exploited the vulnerability could obtain information to
    further compromise the users system.  (CVE-2018-0750)");
  # https://support.microsoft.com/en-us/help/4056897/windows-7-update-kb4056897
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7fb3e6d3");
  # https://support.microsoft.com/en-us/help/4056894/windows-7-update-kb4056894
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?018fc10e");
  # https://support.microsoft.com/en-us/help/4072698/windows-server-speculative-execution-side-channel-vulnerabilities-prot
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8902cebb");
  # https://support.microsoft.com/en-us/help/4072699/windows-security-updates-and-antivirus-software
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67de4887");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV180002
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?573cb1ef");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB4056897 or Cumulative Update KB4056894
as well as refer to the KB4072698 article for additional information.

Note: Due to a compatibility issue with some antivirus software
products, it may not be possible to apply the required updates.
See Microsoft KB article 4072699 for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0762");
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
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS18-01";
kbs = make_list('4056897', '4056894');
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win7:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"6.1",
                   sp:1,
                   rollup_date:"01_2018",
                   bulletin:bulletin,
                   rollup_kb_list:[4056897, 4056894])
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
