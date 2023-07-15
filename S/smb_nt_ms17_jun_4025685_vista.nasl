#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(100785);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2017-0222",
    "CVE-2017-0267",
    "CVE-2017-0268",
    "CVE-2017-0269",
    "CVE-2017-0270",
    "CVE-2017-0271",
    "CVE-2017-0272",
    "CVE-2017-0273",
    "CVE-2017-0274",
    "CVE-2017-0275",
    "CVE-2017-0276",
    "CVE-2017-0277",
    "CVE-2017-0278",
    "CVE-2017-0279",
    "CVE-2017-0280",
    "CVE-2017-8464",
    "CVE-2017-8543",
    "CVE-2017-8552"
  );
  script_bugtraq_id(
    98127,
    98259,
    98260,
    98261,
    98263,
    98264,
    98265,
    98266,
    98267,
    98268,
    98270,
    98271,
    98272,
    98273,
    98274,
    98818,
    98824,
    99035
  );
  script_xref(name:"MSKB", value:"4018271");
  script_xref(name:"MSKB", value:"4018466");
  script_xref(name:"MSKB", value:"4019204");
  script_xref(name:"MSKB", value:"4021903");
  script_xref(name:"MSKB", value:"4024402");
  script_xref(name:"MSFT", value:"MS17-4018271");
  script_xref(name:"MSFT", value:"MS17-4018466");
  script_xref(name:"MSFT", value:"MS17-4019204");
  script_xref(name:"MSFT", value:"MS17-4021903");
  script_xref(name:"MSFT", value:"MS17-4024402");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/10");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/25");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/14");

  script_name(english:"Microsoft Security Advisory 4025685: Windows Vista (June 2017)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows Vista host is missing a security update. It is,
therefore, affected by the following vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Internet Explorer due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit this, by convincing a user to visit a
    specially crafted website, to execute arbitrary code in
    the context of the current user. (CVE-2017-0222)

  - Multiple information disclosure vulnerabilities exist in
    the Microsoft Server Message Block 1.0 (SMBv1) server
    when handling certain requests. An unauthenticated,
    remote attacker can exploit these, via a specially
    crafted packet, to disclose sensitive information.
    (CVE-2017-0267, CVE-2017-0268, CVE-2017-0270,
    CVE-2017-0271, CVE-2017-0274, CVE-2017-0275,
    CVE-2017-0276)

  - Multiple denial of service vulnerabilities exist in
    Microsoft Server Message Block (SMB) when handling a
    specially crafted request to the server. An
    unauthenticated, remote attacker can exploit these, via
    a crafted SMB request, to cause the system to stop
    responding. (CVE-2017-0269, CVE-2017-0273,
    CVE-2017-0280)

  - Multiple remote code execution vulnerabilities exist in
    the Microsoft Server Message Block 1.0 (SMBv1) server
    when handling certain requests. An unauthenticated,
    remote attacker can exploit these, via a specially
    crafted packet, to execute arbitrary code on a target
    server. (CVE-2017-0272, CVE-2017-0277, CVE-2017-0278,
    CVE-2017-0279)

  - A remote code execution vulnerability exists in Windows
    due to improper handling of shortcuts. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to insert a removable drive containing
    a malicious shortcut and binary, to automatically
    execute arbitrary code in the context of the current
    user. (CVE-2017-8464)

  - A remote code execution vulnerability exists in the
    Windows Search functionality due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit this, via a specially crafted SMB message,
    to execute arbitrary code. (CVE-2017-8543)

  - An information disclosure vulnerability exists in the
    GDI component due to improper handling of objects in
    memory. An unauthenticated, remote attacker can exploit
    this, by convincing a user to open a specially crafted
    document or visit a specially crafted website, to
    disclose the contents of memory. (CVE-2017-8552)");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2017/4025685");
  # https://support.microsoft.com/en-us/help/4025687/microsoft-security-advisory-4025685-guidance-for-older-platforms
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0780816");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista.");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "smb_check_rollup.nasl");
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

bulletin = "MS17-06";
kbs = make_list(
  "4018271",
  "4018466",
  "4021903",
  "4024402",
  "4019204"
);

vuln = 0;

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

# Only Vista
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Vista" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share))
  audit(AUDIT_SHARE_FAIL, share);

if (
  # 4018271 aka CVE-2017-0222
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.16896", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"4018271") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21007", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"4018271") ||

  # 4018466 aka CVE-2017-0267 to 0280
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"netevent.dll", version:"6.0.6002.19673", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"4018466") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"netevent.dll", version:"6.0.6002.24089", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"4018466") ||

  # 4021903 aka CVE-2017-8464
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"shell32.dll", version:"6.0.6002.19785", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"4021903") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"shell32.dll", version:"6.0.6002.24102", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"4021903") ||

  # 4024402 aka CVE-2017-8543
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"searchindexer.exe", version:"7.0.6002.19805", min_version:"7.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"4024402") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"searchindexer.exe", version:"7.0.6002.24123", min_version:"7.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"4024402") ||

  # 4019204 aka CVE-2017-8552
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.19778", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"4019204") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.24095", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"4019204")
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
