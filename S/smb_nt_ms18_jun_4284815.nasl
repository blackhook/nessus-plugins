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
  script_id(110484);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id(
    "CVE-2018-0978",
    "CVE-2018-1036",
    "CVE-2018-1040",
    "CVE-2018-8169",
    "CVE-2018-8205",
    "CVE-2018-8207",
    "CVE-2018-8210",
    "CVE-2018-8225",
    "CVE-2018-8249",
    "CVE-2018-8251",
    "CVE-2018-8267"
  );
  script_bugtraq_id(
    104356,
    104360,
    104363,
    104364,
    104379,
    104389,
    104391,
    104395,
    104398,
    104404,
    104407
  );
  script_xref(name:"MSKB", value:"4284878");
  script_xref(name:"MSKB", value:"4284815");
  script_xref(name:"MSFT", value:"MS18-4284878");
  script_xref(name:"MSFT", value:"MS18-4284815");

  script_name(english:"KB4284878: Windows 8.1 and Windows Server 2012 R2 June 2018 Security Update");
  script_summary(english:"Checks for rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4284878
or cumulative update 4284815. It is, therefore, affected by
multiple vulnerabilities :

  - An elevation of privilege vulnerability exists when the
    (Human Interface Device) HID Parser Library driver
    improperly handles objects in memory. An attacker who
    successfully exploited this vulnerability could run
    processes in an elevated context.  (CVE-2018-8169)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2018-0978,
    CVE-2018-8249)

  - A memory corruption vulnerability exists when Windows
    Media Foundation improperly handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could install programs; view, change, or delete data; or
    create new accounts with full user rights. There are
    multiple ways an attacker could exploit the
    vulnerability, such as by convincing a user to open a
    specially crafted document, or by convincing a user to
    visit a malicious webpage. The security update addresses
    the vulnerability by correcting how Windows Media
    Foundation handles objects in memory. (CVE-2018-8251)

  - A remote code execution vulnerability exists in Windows
    Domain Name System (DNS) DNSAPI.dll when it fails to
    properly handle DNS responses. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the Local System
    Account.  (CVE-2018-8225)

  - A denial of service vulnerability exists when Windows
    improperly handles objects in memory. An attacker who
    successfully exploited the vulnerability could cause a
    target system to stop responding.  (CVE-2018-8205)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2018-8267)

  - A remote code execution vulnerability exists when
    Windows improperly handles objects in memory. An
    attacker who successfully exploited these
    vulnerabilities could take control of an affected
    system.  (CVE-2018-8210)

  - A denial of service vulnerability exists in the way that
    the Windows Code Integrity Module performs hashing. An
    attacker who successfully exploited the vulnerability
    could cause a system to stop responding. Note that the
    denial of service condition would not allow an attacker
    to execute code or to elevate user privileges. However,
    the denial of service condition could prevent authorized
    users from using system resources. An attacker could
    host a specially crafted file in a website or SMB share.
    The attacker could also take advantage of compromised
    websites, or websites that accept or host user-provided
    content or advertisements, by adding specially crafted
    content that could exploit the vulnerability. However,
    in all cases an attacker would have no way to force
    users to view the attacker-controlled content. Instead,
    an attacker would have to convince users to take action,
    typically via an enticement in email or instant message,
    or by getting them to open an email attachment. The
    security update addresses the vulnerability by modifying
    how the Code Integrity Module performs hashing.
    (CVE-2018-1040)

  - An elevation of privilege vulnerability exists when NTFS
    improperly checks access. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context.  (CVE-2018-1036)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2018-8207)");
  # https://support.microsoft.com/en-us/help/4284878/windows-81-update-kb4284878
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?224e0ffb");
  # https://support.microsoft.com/en-us/help/4284815/windows-81-update-kb4284815
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43458adc");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB4284878 or Cumulative Update KB4284815.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8225");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
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
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS18-06";
kbs = make_list('4284878', '4284815');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Windows 8 EOL
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"6.3",
                   sp:0,
                   rollup_date:"06_2018",
                   bulletin:bulletin,
                   rollup_kb_list:[4284878, 4284815])
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
