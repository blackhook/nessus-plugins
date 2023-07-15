#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(100759);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2017-0193",
    "CVE-2017-0216",
    "CVE-2017-0218",
    "CVE-2017-0219",
    "CVE-2017-0282",
    "CVE-2017-0283",
    "CVE-2017-0284",
    "CVE-2017-0285",
    "CVE-2017-0287",
    "CVE-2017-0288",
    "CVE-2017-0289",
    "CVE-2017-0291",
    "CVE-2017-0292",
    "CVE-2017-0294",
    "CVE-2017-0296",
    "CVE-2017-0297",
    "CVE-2017-0298",
    "CVE-2017-0299",
    "CVE-2017-0300",
    "CVE-2017-8460",
    "CVE-2017-8462",
    "CVE-2017-8464",
    "CVE-2017-8465",
    "CVE-2017-8466",
    "CVE-2017-8468",
    "CVE-2017-8470",
    "CVE-2017-8471",
    "CVE-2017-8473",
    "CVE-2017-8474",
    "CVE-2017-8475",
    "CVE-2017-8476",
    "CVE-2017-8477",
    "CVE-2017-8478",
    "CVE-2017-8479",
    "CVE-2017-8480",
    "CVE-2017-8481",
    "CVE-2017-8482",
    "CVE-2017-8483",
    "CVE-2017-8484",
    "CVE-2017-8485",
    "CVE-2017-8489",
    "CVE-2017-8490",
    "CVE-2017-8491",
    "CVE-2017-8492",
    "CVE-2017-8493",
    "CVE-2017-8494",
    "CVE-2017-8515",
    "CVE-2017-8517",
    "CVE-2017-8518",
    "CVE-2017-8522",
    "CVE-2017-8523",
    "CVE-2017-8524",
    "CVE-2017-8527",
    "CVE-2017-8530",
    "CVE-2017-8531",
    "CVE-2017-8532",
    "CVE-2017-8533",
    "CVE-2017-8543",
    "CVE-2017-8544",
    "CVE-2017-8547",
    "CVE-2017-8548",
    "CVE-2017-8549",
    "CVE-2017-8554",
    "CVE-2017-8575",
    "CVE-2017-8576",
    "CVE-2017-8579"
  );
  script_bugtraq_id(
    98818,
    98819,
    98820,
    98821,
    98824,
    98826,
    98833,
    98835,
    98836,
    98837,
    98839,
    98840,
    98843,
    98844,
    98845,
    98846,
    98847,
    98848,
    98849,
    98850,
    98852,
    98853,
    98854,
    98855,
    98856,
    98857,
    98858,
    98859,
    98860,
    98862,
    98863,
    98865,
    98867,
    98869,
    98870,
    98878,
    98884,
    98885,
    98887,
    98895,
    98896,
    98897,
    98898,
    98900,
    98901,
    98902,
    98903,
    98914,
    98918,
    98920,
    98922,
    98923,
    98926,
    98928,
    98929,
    98930,
    98932,
    98933,
    98942,
    98954,
    98955,
    99210,
    99212,
    99215
  );
  script_xref(name:"MSKB", value:"4022714");
  script_xref(name:"MSFT", value:"MS17-4022714");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/10");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/14");

  script_name(english:"KB4022714: Windows 10 Version 1511 June 2017 Cumulative Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows 10 version 1511 host is missing security update
KB4022714. It is, therefore, affected by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists in
    Windows Hyper-V instruction emulation due to a failure
    to properly enforce privilege levels. An attacker on a
    guest operating system can exploit this to gain elevated
    privileges on the guest. Note that the host operating
    system is not vulnerable. (CVE-2017-0193)

  - Multiple security bypass vulnerabilities exist in
    Device Guard. A local attacker can exploit these, via a
    specially crafted script, to bypass the Device Guard
    Code Integrity policy and inject arbitrary code into a
    trusted PowerShell process. (CVE-2017-0216,
    CVE-2017-0218, CVE-2017-0219)

  - Multiple information disclosure vulnerabilities exist in
    Windows Uniscribe due to improper handling of objects in
    memory. An unauthenticated, remote attacker can exploit
    these, by convincing a user to visit a specially crafted
    website or to open a specially crafted document, to
    disclose the contents of memory. (CVE-2017-0282,
    CVE-2017-0284, CVE-2017-0285)

  - A remote code execution vulnerability exists in
    Windows Uniscribe software due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit this, by convincing a user to visit a
    specially crafted website or to open a specially crafted
    document, to execute arbitrary code in the context
    of the current user. (CVE-2017-0283)

  - Multiple information disclosure vulnerabilities exist in
    the Windows GDI component due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit these, by convincing a user to visit a
    specially crafted website or open a specially crafted
    document, to disclose the contents of memory.
    (CVE-2017-0287, CVE-2017-0288, CVE-2017-0289,
    CVE-2017-8531, CVE-2017-8532, CVE-2017-8533)

  - Multiple remote code execution vulnerabilities exist in
    Microsoft Windows due to improper parsing of PDF files.
    An unauthenticated, remote attacker can exploit these,
    by convincing a user to open a specially crafted PDF
    file, to execute arbitrary code in the context of the
    current user. (CVE-2017-0291, CVE-2017-0292)

  - A remote code execution vulnerability exists in
    Microsoft Windows due to improper handling of cabinet
    files. An unauthenticated, remote attacker can exploit
    this, by convincing a user to open a specially crafted
    cabinet file, to execute arbitrary code in the context
    of the current user. (CVE-2017-0294)

  - An elevation of privilege vulnerability exists in
    tdx.sys due to a failure to check the length of a buffer
    prior to copying memory to it. A local attacker can
    exploit this, via a specially crafted application, to
    execute arbitrary code in an elevated context.
    (CVE-2017-0296)

  - An elevation of privilege vulnerability exists in the
    Windows kernel due to improper handling of objects in
    memory. A local attacker can exploit this, via a
    specially crafted application, to execute arbitrary code
    with elevated permissions. (CVE-2017-0297)

  - An elevation of privilege vulnerability exists in the
    DCOM object in Helppane.exe, when configured to run as
    the interactive user, due to a failure to properly
    authenticate the client. An authenticated, remote
    attacker can exploit this, via a specially crafted
    application, to run arbitrary code in another user's
    session after that user has logged on to the same system
    using Terminal Services or Fast User Switching.
    (CVE-2017-0298)

  - Multiple information disclosure vulnerabilities exist in
    the Windows kernel due to improper initialization of
    objects in memory. An authenticated, remote attacker can
    exploit these, via a specially crafted application, to
    disclose the base address of the kernel driver.
    (CVE-2017-0299, CVE-2017-0300, CVE-2017-8462,
    CVE-2017-8485)

  - An information disclosure vulnerability exists in
    Microsoft Windows due to improper parsing of PDF files.
    An unauthenticated, remote attacker can exploit this, by
    convincing a user to open a specially crafted PDF file,
    to disclose the contents of memory. (CVE-2017-8460)

  - A remote code execution vulnerability exists in Windows
    due to improper handling of shortcuts. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to insert a removable drive containing
    a malicious shortcut and binary, to automatically
    execute arbitrary code in the context of the current
    user. (CVE-2017-8464)

  - Multiple elevation of privilege vulnerabilities exist in
    the Windows kernel-mode driver due to improper handling
    of objects in memory. A local attacker can exploit
    these, via a specially crafted application, to run
    processes in an elevated context. (CVE-2017-8465,
    CVE-2017-8466, CVE-2017-8468)

  - Multiple information disclosure vulnerabilities exist in
    the Windows kernel due to improper initialization of
    objects in memory. An authenticated, remote attacker can
    exploit these, via a specially crafted application, to
    disclose sensitive information. (CVE-2017-8470,
    CVE-2017-8471, CVE-2017-8473, CVE-2017-8474,
    CVE-2017-8475, CVE-2017-8476, CVE-2017-8477,
    CVE-2017-8478, CVE-2017-8479, CVE-2017-8480,
    CVE-2017-8481, CVE-2017-8482, CVE-2017-8483,
    CVE-2017-8484, CVE-2017-8489, CVE-2017-8490,
    CVE-2017-8491, CVE-2017-8492)

  - A security bypass vulnerability exists due to a failure
    to enforce case sensitivity for certain variable checks.
    A local attacker can exploit this, via a specially
    crafted application, to bypass Unified Extensible
    Firmware Interface (UEFI) variable security.
    (CVE-2017-8493)

  - An elevation of privilege vulnerability exists in the
    Windows Secure Kernel Mode feature due to a failure to
    properly handle objects in memory. A local attacker can
    exploit this, via a specially crafted application, to
    bypass virtual trust levels (VTL). (CVE-2017-8494)

  - A denial of service vulnerability exists in Windows due
    to improper handling of kernel mode requests. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted kernel mode request, to cause the
    machine to stop responding or rebooting. (CVE-2017-8515)

  - Multiple remote code execution vulnerabilities exist in
    Microsoft browsers in the JavaScript engines due to
    improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit these, by
    convincing a user to visit a specially crafted website,
    to execute arbitrary code in the context of the current
    user. (CVE-2017-8517, CVE-2017-8522, CVE-2017-8524,
    CVE-2017-8548)

  - A same-origin policy bypass vulnerability exists in
    Microsoft Edge due to a failure to properly apply the
    Same Origin Policy for HTML elements. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to follow a link, to load a page with
    malicious content. (CVE-2017-8523)

  - A remote code execution vulnerability exists in the
    Windows font library due to improper handling of
    embedded fonts. An unauthenticated, remote attacker can
    exploit this, by convincing a user to visit a specially
    crafted website or open a specially crafted Microsoft
    document, to execute arbitrary code in the context of
    the current user. (CVE-2017-8527)

  - A same-origin policy bypass vulnerability exists in
    Microsoft Edge due to a failure to properly enforce
    same-origin policies. An unauthenticated, remote
    attacker can exploit this, by convincing a user to visit
    a specially crafted website, to disclose information
    from origins outside the current one. (CVE-2017-8530)

  - A remote code execution vulnerability exists in the
    Windows Search functionality due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit this, via a specially crafted SMB message,
    to execute arbitrary code. (CVE-2017-8543)

  - An information disclosure vulnerability exists in the
    Windows Search functionality due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit this, via a specially crafted SMB message,
    to disclose sensitive information. (CVE-2017-8544)

  - A remote code execution vulnerability exists in Internet
    Explorer due to improper handling of objects in memory.
    An unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a specially crafted website,
    to execute arbitrary code in the context of the current
    user. (CVE-2017-8547)

  - A remote code execution vulnerability exists in
    Microsoft Edge in the JavaScript scripting engine due to
    improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a specially crafted website,
    to execute arbitrary code in the context of the current
    user. (CVE-2017-8549)

  - An information disclosure vulnerability exists in the
    Windows Graphics component due to improper handling of
    objects in memory. An authenticated, remote attacker can
    exploit this, via a specially crafted application, to
    disclose sensitive information. (CVE-2017-8575)

  - An elevation of privilege vulnerability exists in the
    Windows Graphics component due to improper
    initialization of objects in memory. A local attacker
    can exploit this, via a specially crafted application,
    to execute arbitrary code in kernel mode.
    (CVE-2017-8576)

  - An elevation of privilege vulnerability exists DirectX
    due to improper handling of objects in memory. A local
    attacker can exploit this, via a specially crafted
    application, to execute arbitrary code in kernel mode.
    (CVE-2017-8576)

  - An information disclosure vulnerability exists in the
    Windows kernel due to improper handling of objects in
    memory. An authenticated, remote attacker can exploit
    this, via a specially crafted application, to disclose
    the contents of memory. (CVE-2017-8554)");
  # https://support.microsoft.com/en-us/help/4022714/windows-10-update-kb4022714
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46ed25c8");
  script_set_attribute(attribute:"solution", value:
"Apply security update KB4022714 as well as refer to the KB article for additional information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8543");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'LNK Code Execution Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "smb_check_rollup.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS17-06';
kb = make_list(
  '4022714' # 10 1151
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kb, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("2016" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # 10 (1511)
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"10586",
                   rollup_date: "06_2017",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(4022714)))
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
