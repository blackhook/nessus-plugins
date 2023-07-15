#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(100791);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2017-0176",
    "CVE-2017-0222",
    "CVE-2017-0267",
    "CVE-2017-7269",
    "CVE-2017-8461",
    "CVE-2017-8487",
    "CVE-2017-8543",
    "CVE-2017-8552"
  );
  script_bugtraq_id(
    97127,
    98127,
    98259,
    98752,
    98824,
    99012,
    99013,
    99035
  );
  script_xref(name:"MSKB", value:"3197835");
  script_xref(name:"MSKB", value:"4018271");
  script_xref(name:"MSKB", value:"4018466");
  script_xref(name:"MSKB", value:"4019204");
  script_xref(name:"MSKB", value:"4022747");
  script_xref(name:"MSKB", value:"4024323");
  script_xref(name:"MSKB", value:"4024402");
  script_xref(name:"MSKB", value:"4025218");
  script_xref(name:"MSFT", value:"MS17-3197835");
  script_xref(name:"MSFT", value:"MS17-4018271");
  script_xref(name:"MSFT", value:"MS17-4018466");
  script_xref(name:"MSFT", value:"MS17-4019204");
  script_xref(name:"MSFT", value:"MS17-4022747");
  script_xref(name:"MSFT", value:"MS17-4024323");
  script_xref(name:"MSFT", value:"MS17-4024402");
  script_xref(name:"MSFT", value:"MS17-4025218");
  script_xref(name:"EDB-ID", value:"41738");
  script_xref(name:"EDB-ID", value:"41992");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/25");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/14");

  script_name(english:"Microsoft Security Advisory 4025685: Guidance for older platforms (XP / 2003) (EXPLODINGCAN)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by one or more of the following vulnerabilities :

  - A remote code execution vulnerability exists in how the
    Remote Desktop Protocol (RDP) handles requests if the
    RDP server has Smart Card authentication enabled. An
    authenticated, remote attacker can exploit this, via a
    specially crafted application, to execute arbitrary code
    with full user privileges. (CVE-2017-0176)

  - A remote code execution vulnerability exists in
    Microsoft Internet Explorer due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit this, by convincing a user to visit a
    specially crafted website, to execute arbitrary code in
    the context of the current user. (CVE-2017-0222)

  - An information disclosure vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to disclose sensitive information.
    (CVE-2017-0267)

  - A buffer overflow condition exists in the IIS WebDAV
    service due to improper handling of the 'If' header in a
    PROPFIND request. An unauthenticated, remote attacker
    can exploit this, via a specially crafted request, to
    cause a denial of service condition or the execution of
    arbitrary code. This vulnerability, also known as
    EXPLODINGCAN, is one of multiple Equation Group
    vulnerabilities and exploits disclosed on 2017/04/14 by
    a group known as the Shadow Brokers. (CVE-2017-7269)

  - A remote code execution vulnerability exists in how the
    Remote Desktop Protocol (RDP) handles requests if the
    RDP server has Routing and Remote Access enabled. An
    authenticated, remote attacker can exploit this, via a
    specially crafted application, to execute arbitrary code
    with full user privileges. (CVE-2017-8461)

  - A remote code execution vulnerability exists in Windows
    OLE, specifically in olecnv32.dll, due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to visit a specially crafted website or to open a
    specially crafted file or email, to execute arbitrary
    code in the context of the current user. (CVE-2017-8487)

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
  # https://support.microsoft.com/en-us/help/4025687/microsoft-security-advisory-4025685-guidance-for-older-platforms
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0780816");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP and 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8543");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft IIS WebDav ScStoragePathFromUrl Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

kbs = make_list(
  '3197835',
  '4018271',
  '4018466',
  '4019204',
  '4022747',
  '4024323',
  '4024402',
  '4025218'
);

bulletin = 'MS17-06';

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'2,3', win2003:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = FALSE;
if ('XP' >< productname)
{
  if (
    # Windows XP SP3 (x86)
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"win32k.sys", version:"5.1.2600.7258", min_version:"5.1.2600.5000", dir:"\system32", bulletin:bulletin, kb:"4019204", arch:"x86") ||
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"query.dll", version:"5.1.2600.7273", min_version:"5.1.2600.5000", dir:"\system32", bulletin:bulletin, kb:"4024402", arch:"x86") ||
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"olecnv32.dll", version:"5.1.2600.7285", min_version:"5.1.2600.5000", dir:"\system32", bulletin:bulletin, kb:"4025218", arch:"x86") ||
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"rasmxs.dll", version:"5.1.2600.7272", min_version:"5.1.2600.5000", dir:"\system32", bulletin:bulletin, kb:"4024323", arch:"x86") ||
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"httpext.dll", version:"6.0.2600.7150", min_version:"6.0.0.0", dir:"\system32\inetsrv", bulletin:bulletin, kb:"3197835", arch:"x86") ||
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"srv.sys", version:"5.1.2600.7238", min_version:"5.1.2600.5000", dir:"\system32\drivers", bulletin:bulletin, kb:"4018466", arch:"x86") ||
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"mshtml.dll", version:"8.0.6001.23942", min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:"4018271", arch:"x86") ||
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"gpkcsp.dll", version:"5.1.2600.7264", min_version:"5.1.2600.5000", dir:"\system32", bulletin:bulletin, kb:"4022747", arch:"x86") ||

    # Windows XP SP2 (x64)
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"win32k.sys", version:"5.2.3790.6080", min_version:"5.2.3790.3000", dir:"\system32", bulletin:bulletin, kb:"4019204", arch:"x64") ||
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"query.dll", version:"5.2.3790.6100", min_version:"5.2.3790.3000", dir:"\system32", bulletin:bulletin, kb:"4024402", arch:"x64") ||
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"olecnv32.dll", version:"5.2.3790.6113", min_version:"5.2.3790.3000", dir:"\system32", bulletin:bulletin, kb:"4025218", arch:"x64") ||
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"rasmxs.dll", version:"5.2.3790.6099", min_version:"5.2.3790.3000", dir:"\system32", bulletin:bulletin, kb:"4024323", arch:"x64") ||
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"httpext.dll", version:"6.0.3790.5955", min_version:"6.0.0.0", dir:"\system32\inetsrv", bulletin:bulletin, kb:"3197835", arch:"x64") ||
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"srv.sys", version:"5.2.3790.6051", min_version:"5.2.3790.3000", dir:"\system32\drivers", bulletin:bulletin, kb:"4018466", arch:"x64") ||
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"mshtml.dll", version:"8.0.6001.23942", min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:"4018271", arch:"x64") ||
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"gpkcsp.dll", version:"5.2.3790.6093", min_version:"5.2.3790.3000", dir:"\system32", bulletin:bulletin, kb:"4022747", arch:"x64")
  ) vuln = TRUE;
}
else if ('2003' >< productname)
{
  if (
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"win32k.sys", version:"5.2.3790.6080", min_version:"5.2.3790.3000", dir:"\system32", bulletin:bulletin, kb:"4019204") ||
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"query.dll", version:"5.2.3790.6100", min_version:"5.2.3790.3000", dir:"\system32", bulletin:bulletin, kb:"4024402") ||
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"olecnv32.dll", version:"5.2.3790.6113", min_version:"5.2.3790.3000", dir:"\system32", bulletin:bulletin, kb:"4025218") ||
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"rasmxs.dll", version:"5.2.3790.6099", min_version:"5.2.3790.3000", dir:"\system32", bulletin:bulletin, kb:"4024323") ||
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"httpext.dll", version:"6.0.3790.5955", min_version:"6.0.0.0", dir:"\system32\inetsrv", bulletin:bulletin, kb:"3197835") ||
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"srv.sys", version:"5.2.3790.6051", min_version:"5.2.3790.3000", dir:"\system32\drivers", bulletin:bulletin, kb:"4018466") ||
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"gpkcsp.dll", version:"5.2.3790.6093", min_version:"5.2.3790.3000", dir:"\system32", bulletin:bulletin, kb:"4022747")
  ) vuln = TRUE;
}

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
