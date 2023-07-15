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
  script_id(109610);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2018-0765",
    "CVE-2018-0824",
    "CVE-2018-0954",
    "CVE-2018-0955",
    "CVE-2018-0959",
    "CVE-2018-1039",
    "CVE-2018-8124",
    "CVE-2018-8127",
    "CVE-2018-8136",
    "CVE-2018-8145",
    "CVE-2018-8164",
    "CVE-2018-8166",
    "CVE-2018-8167",
    "CVE-2018-8174",
    "CVE-2018-8897"
  );
  script_xref(name:"MSKB", value:"4103730");
  script_xref(name:"MSKB", value:"4103726");
  script_xref(name:"MSFT", value:"MS18-4103730");
  script_xref(name:"MSFT", value:"MS18-4103726");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/15");

  script_name(english:"KB4103726: Windows Server 2012 May 2018 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4103726
or cumulative update 4103730. It is, therefore, affected by
multiple vulnerabilities :

  - An elevation of privilege vulnerability exists when the
    Windows kernel fails to properly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could run arbitrary code in kernel mode.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights.  (CVE-2018-8897)

  - An elevation of privilege vulnerability exists when the
    Windows Common Log File System (CLFS) driver improperly
    handles objects in memory. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context.  (CVE-2018-8167)

  - A security feature bypass vulnerability exists in .Net
    Framework which could allow an attacker to bypass Device
    Guard. An attacker who successfully exploited this
    vulnerability could circumvent a User Mode Code
    Integrity (UMCI) policy on the machine.  (CVE-2018-1039)

  - An information disclosure vulnerability exists when
    Chakra improperly discloses the contents of its memory,
    which could provide an attacker with information to
    further compromise the users computer or data.
    (CVE-2018-8145)

  - A remote code execution vulnerability exists in the way
    that Windows handles objects in memory. An attacker who
    successfully exploited the vulnerability could execute
    arbitrary code with elevated permissions on a target
    system.  (CVE-2018-8136)

  - A remote code execution vulnerability exists in the way
    the scripting engine handles objects in memory in
    Microsoft browsers. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2018-0954)

  - A remote code execution vulnerability exists when
    Windows Hyper-V on a host server fails to properly
    validate input from an authenticated user on a guest
    operating system.  (CVE-2018-0959)

  - A remote code execution vulnerability exists in
    Microsoft COM for Windows when it fails to
    properly handle serialized objects. An attacker who
    successfully exploited the vulnerability could use a
    specially crafted file or script to perform actions. In
    an email attack scenario, an attacker could exploit the
    vulnerability by sending the specially crafted file to
    the user and convincing the user to open the file.
    (CVE-2018-0824)

  - A remote code execution vulnerability exists in the way
    that the VBScript engine handles objects in memory. The
    vulnerability could corrupt memory in such a way that an
    attacker could execute arbitrary code in the context of
    the current user. An attacker who successfully exploited
    the vulnerability could gain the same user rights as the
    current user.  (CVE-2018-8174)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2018-8127)

  - An elevation of privilege vulnerability exists in
    Windows when the Win32k component fails to properly
    handle objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2018-8124, CVE-2018-8164,
    CVE-2018-8166)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2018-0955)

  - A denial of service vulnerability exists when .NET and
    .NET Core improperly process XML documents. An attacker
    who successfully exploited this vulnerability could
    cause a denial of service against a .NET application. A
    remote unauthenticated attacker could exploit this
    vulnerability by issuing specially crafted requests to a
    .NET (or .NET core) application. The update addresses
    the vulnerability by correcting how .NET and .NET Core
    applications handle XML document processing.
    (CVE-2018-0765)");
  # https://support.microsoft.com/en-us/help/4103730/windows-server-2012-update-kb4103730
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a47bd1fd");
  # https://support.microsoft.com/en-us/help/4103726/windows-server-2012-update-kb4103726
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?988e96ea");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB4103726 or Cumulative Update KB4103730.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8136");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-8897");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows POP/MOV SS Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS18-05";
kbs = make_list('4103730', '4103726');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Windows 8 EOL
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"6.2",
                   sp:0,
                   rollup_date:"05_2018",
                   bulletin:bulletin,
                   rollup_kb_list:[4103730, 4103726])
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
