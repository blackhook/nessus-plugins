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
  script_id(111686);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/29");

  script_cve_id(
    "CVE-2018-3615",
    "CVE-2018-3620",
    "CVE-2018-3646",
    "CVE-2018-0952",
    "CVE-2018-8200",
    "CVE-2018-8204",
    "CVE-2018-8266",
    "CVE-2018-8316",
    "CVE-2018-8339",
    "CVE-2018-8341",
    "CVE-2018-8343",
    "CVE-2018-8344",
    "CVE-2018-8345",
    "CVE-2018-8348",
    "CVE-2018-8349",
    "CVE-2018-8351",
    "CVE-2018-8353",
    "CVE-2018-8355",
    "CVE-2018-8357",
    "CVE-2018-8360",
    "CVE-2018-8370",
    "CVE-2018-8371",
    "CVE-2018-8372",
    "CVE-2018-8373",
    "CVE-2018-8381",
    "CVE-2018-8385",
    "CVE-2018-8389",
    "CVE-2018-8394",
    "CVE-2018-8398",
    "CVE-2018-8401",
    "CVE-2018-8403",
    "CVE-2018-8404",
    "CVE-2018-8405",
    "CVE-2018-8406"
  );
  script_bugtraq_id(
    104977,
    104978,
    104980,
    104982,
    104983,
    104984,
    104986,
    104987,
    104992,
    104995,
    104999,
    105001,
    105006,
    105007,
    105008,
    105011,
    105012,
    105027,
    105030,
    105048
  );
  script_xref(name:"MSKB", value:"4343892");
  script_xref(name:"MSFT", value:"MS18-4343892");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/18");

  script_name(english:"KB4343892: Windows 10 August 2018 Security Update (Foreshadow)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4343892.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in the way
    that Microsoft browsers access objects in memory. The
    vulnerability could corrupt memory in a way that could
    allow an attacker to execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2018-8403)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2018-8341, CVE-2018-8348)

  - A remote code execution vulnerability exists when the
    Windows font library improperly handles specially
    crafted embedded fonts. An attacker who successfully
    exploited the vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights.  (CVE-2018-8344)

  - An elevation of privilege vulnerability exists in
    Windows when the Win32k component fails to properly
    handle objects in memory. An attacker who successfully
    exploited this vulnerability could run arbitrary code in
    kernel mode. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights.  (CVE-2018-8404)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly validates hyperlinks before
    loading executable libraries. An attacker who
    successfully exploited this vulnerability could take
    control of an affected system. An attacker could then
    install programs; view, change, or delete data; or
    create new accounts with full user rights.
    (CVE-2018-8316)

  - A security feature bypass vulnerability exists in Device
    Guard that could allow an attacker to inject malicious
    code into a Windows PowerShell session. An attacker who
    successfully exploited this vulnerability could inject
    code into a trusted PowerShell process to bypass the
    Device Guard Code Integrity policy on the local machine.
    (CVE-2018-8200, CVE-2018-8204)

  - An Elevation of Privilege vulnerability exists when
    Diagnostics Hub Standard Collector allows file creation
    in arbitrary locations.  (CVE-2018-0952)

  - A remote code execution vulnerability exists in the way
    the scripting engine handles objects in memory in
    Microsoft browsers. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2018-8355, CVE-2018-8372, CVE-2018-8385)

  - A remote code execution vulnerability exists in the way
    that the Chakra scripting engine handles objects in
    memory in Microsoft Edge. The vulnerability could
    corrupt memory in such a way that an attacker could
    execute arbitrary code in the context of the current
    user. An attacker who successfully exploited the
    vulnerability could gain the same user rights as the
    current user.  (CVE-2018-8266, CVE-2018-8381)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2018-8353, CVE-2018-8371, CVE-2018-8373,
    CVE-2018-8389)

  - A remote code execution vulnerability exists in
    Microsoft Windows that could allow remote code execution
    if a .LNK file is processed. An attacker who
    successfully exploited this vulnerability could gain the
    same user rights as the local user.  (CVE-2018-8345)

  - An elevation of privilege vulnerability exists when the
    DirectX Graphics Kernel (DXGKRNL) driver improperly
    handles objects in memory. An attacker who successfully
    exploited this vulnerability could run processes in an
    elevated context.  (CVE-2018-8401, CVE-2018-8405,
    CVE-2018-8406)

  - A information disclosure vulnerability exists when
    WebAudio Library improperly handles audio requests. An
    attacker who has successfully exploited this
    vulnerability might be able to read privileged data
    across trust boundaries. In browsing scenarios, an
    attacker could convince a user to visit a malicious site
    and leverage the vulnerability to obtain privileged
    information from the browser process, such as sensitive
    data from other opened tabs. An attacker could also
    inject malicious code into advertising networks used by
    trusted sites or embed malicious code on a compromised,
    but trusted, site. The update addresses the
    vulnerability by correcting how the WebAudio Library
    handles audio requests. (CVE-2018-8370)

  - An elevation of privilege vulnerability exists in the
    Network Driver Interface Specification (NDIS) when
    ndis.sys fails to check the length of a buffer prior to
    copying memory to it.  (CVE-2018-8343)

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
    in memory. (CVE-2018-8394, CVE-2018-8398)

  - A remote code execution vulnerability exists in
    &quot;Microsoft COM for Windows&quot; when it fails to
    properly handle serialized objects. An attacker who
    successfully exploited the vulnerability could use a
    specially crafted file or script to perform actions. In
    an email attack scenario, an attacker could exploit the
    vulnerability by sending the specially crafted file to
    the user and convincing the user to open the file.
    (CVE-2018-8349)

  - An elevation of privilege vulnerability exists in the
    Windows Installer when the Windows Installer fails to
    properly sanitize input leading to an insecure library
    loading behavior. A locally authenticated attacker could
    run arbitrary code with elevated system privileges. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts with full user
    rights. The security update addresses the vulnerability
    by correcting the input sanitization error to preclude
    unintended elevation. (CVE-2018-8339)

  - An information disclosure vulnerability exists in
    Microsoft .NET Framework that could allow an attacker to
    access information in multi-tenant environments. The
    vulnerability is caused when .NET Framework is used in
    high-load/high-density network connections where content
    from one stream can blend into another stream.
    (CVE-2018-8360)

  - An information disclosure vulnerability exists when
    affected Microsoft browsers improperly allow cross-frame
    interaction. An attacker who successfully exploited this
    vulnerability could allow an attacker to obtain browser
    frame or window state from a different domain. For an
    attack to be successful, an attacker must persuade a
    user to open a malicious website from a secure website.
    This update addresses the vulnerability by denying
    permission to read the state of the object model, to
    which frames or windows on different domains should not
    have access. (CVE-2018-8351)

  - An elevation of privilege vulnerability exists in
    Microsoft browsers allowing sandbox escape. An attacker
    who successfully exploited the vulnerability could use
    the sandbox escape to elevate privileges on an affected
    system. This vulnerability by itself does not allow
    arbitrary code execution; however, it could allow
    arbitrary code to be run if the attacker uses it in
    combination with another vulnerability (such as a remote
    code execution vulnerability or another elevation of
    privilege vulnerability) that is capable of leveraging
    the elevated privileges when code execution is
    attempted. (CVE-2018-8357)");
  # https://support.microsoft.com/en-us/help/4343892/windows-10-update-kb4343892
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e04d903e");
  # https://support.microsoft.com/en-us/help/4072698/windows-server-speculative-execution-side-channel-vulnerabilities-prot
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8902cebb");
  script_set_attribute(attribute:"solution", value:
"Apply Cumulative Update KB4343892 as well as refer to the KB article for additional information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8349");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_windows_env_vars.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");
include("smb_reg_query.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS18-08";
kbs = make_list('4343892');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"10240",
                   rollup_date:"08_2018",
                   bulletin:bulletin,
                   rollup_kb_list:[4343892])
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
