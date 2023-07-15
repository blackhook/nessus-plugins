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
  script_id(110980);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/18");

  script_cve_id(
    "CVE-2018-0949",
    "CVE-2018-8125",
    "CVE-2018-8202",
    "CVE-2018-8206",
    "CVE-2018-8222",
    "CVE-2018-8242",
    "CVE-2018-8260",
    "CVE-2018-8275",
    "CVE-2018-8280",
    "CVE-2018-8282",
    "CVE-2018-8284",
    "CVE-2018-8287",
    "CVE-2018-8288",
    "CVE-2018-8290",
    "CVE-2018-8291",
    "CVE-2018-8296",
    "CVE-2018-8304",
    "CVE-2018-8307",
    "CVE-2018-8308",
    "CVE-2018-8309",
    "CVE-2018-8313",
    "CVE-2018-8356"
  );
  script_bugtraq_id(
    104617,
    104620,
    104622,
    104623,
    104629,
    104631,
    104632,
    104634,
    104635,
    104636,
    104637,
    104638,
    104642,
    104644,
    104648,
    104664,
    104665,
    104666,
    104667,
    104668,
    104669,
    104670
  );
  script_xref(name:"MSKB", value:"4338814");
  script_xref(name:"MSFT", value:"MS18-4338814");

  script_name(english:"KB4338814: Windows 10 Version 1607 and Windows Server 2016 July 2018 Security Update");
  script_summary(english:"Checks for rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4338814.
It is, therefore, affected by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists in .NET
    Framework which could allow an attacker to elevate their
    privilege level.  (CVE-2018-8202)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2018-8242, CVE-2018-8296)

  - A denial of service vulnerability exists in Windows
    Domain Name System (DNS) DNSAPI.dll when it fails to
    properly handle DNS responses. An attacker who
    successfully exploited the vulnerability could cause a
    system to stop responding. Note that the denial of
    service condition would not allow an attacker to execute
    code or to elevate user privileges. However, the denial
    of service condition could prevent authorized users from
    using system resources.  (CVE-2018-8304)

  - A denial of service vulnerability exists when Windows
    improperly handles objects in memory. An attacker who
    successfully exploited the vulnerability could cause a
    target system to stop responding.  (CVE-2018-8309)

  - A remote code execution vulnerability exists in the way
    that the Chakra scripting engine handles objects in
    memory in Microsoft Edge. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. An attacker who successfully exploited the
    vulnerability could gain the same user rights as the
    current user.  (CVE-2018-8280, CVE-2018-8290)

  - An elevation of privilege vulnerability exists in
    Windows when the Windows kernel-mode driver fails to
    properly handle objects in memory. An attacker who
    successfully exploited this vulnerability could run
    arbitrary code in kernel mode. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2018-8282)

  - A remote code execution vulnerability exists when
    Microsoft Edge improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that enables an attacker to execute arbitrary code in
    the context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2018-8125,
    CVE-2018-8275)

  - A denial of service vulnerability exists when Windows
    improperly handles File Transfer Protocol (FTP)
    connections. An attacker who successfully exploited the
    vulnerability could cause a target system to stop
    responding.  (CVE-2018-8206)

  - A security feature bypass vulnerability exists in Device
    Guard that could allow an attacker to inject malicious
    code into a Windows PowerShell session. An attacker who
    successfully exploited this vulnerability could inject
    code into a trusted PowerShell process to bypass the
    Device Guard Code Integrity policy on the local machine.
    (CVE-2018-8222)

  - A security feature bypass vulnerability exists when
    Microsoft Internet Explorer improperly handles requests
    involving UNC resources. An attacker who successfully
    exploited the vulnerability could force the browser to
    load data that would otherwise be restricted.
    (CVE-2018-0949)

  - An elevation of privilege vulnerability exists when the
    Windows kernel fails to properly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could run arbitrary code in kernel mode.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights.  (CVE-2018-8308)

  - A security feature bypass vulnerability exists when
    Microsoft WordPad improperly handles embedded OLE
    objects. An attacker who successfully exploited the
    vulnerability could bypass content blocking. In a file-
    sharing attack scenario, an attacker could provide a
    specially crafted document file designed to exploit the
    vulnerability, and then convince a user to open the
    document file. The security update addresses the
    vulnerability by correcting how Microsoft WordPad
    handles input. (CVE-2018-8307)

  - A Remote Code Execution vulnerability exists in .NET
    software when the software fails to check the source
    markup of a file. An attacker who successfully exploited
    the vulnerability could run arbitrary code in the
    context of the current user. If the current user is
    logged on with administrative user rights, an attacker
    could take control of the affected system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2018-8260)

  - An elevation of privilege vulnerability exists in the
    way that the Windows Kernel API enforces permissions. An
    attacker who successfully exploited the vulnerability
    could impersonate processes, interject cross-process
    communication, or interrupt system functionality.
    (CVE-2018-8313)

  - A remote code execution vulnerability exists in the way
    the scripting engine handles objects in memory in
    Microsoft browsers. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2018-8287, CVE-2018-8288, CVE-2018-8291)

  - A remote code execution vulnerability exists when the
    Microsoft .NET Framework fails to validate input
    properly. An attacker who successfully exploited this
    vulnerability could take control of an affected system.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights. Users whose accounts are configured to have
    fewer user rights on the system could be less impacted
    than users who operate with administrative user rights.
    (CVE-2018-8284)

  - A security feature bypass vulnerability exists when
    Microsoft .NET Framework components do not correctly
    validate certificates. An attacker could present expired
    certificates when challenged. The security update
    addresses the vulnerability by ensuring that .NET
    Framework components correctly validate certificates.
    (CVE-2018-8356)");
  # https://support.microsoft.com/en-us/help/4338814/windows-10-update-kb4338814
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a189799");
  script_set_attribute(attribute:"solution", value:
"Apply Cumulative Update KB4338814.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8284");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/10");

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

bulletin = "MS18-07";
kbs = make_list('4338814');

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
                   rollup_date:"07_2018",
                   bulletin:bulletin,
                   rollup_kb_list:[4338814])
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
