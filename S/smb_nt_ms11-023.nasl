#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53380);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/05");

  script_cve_id("CVE-2011-0107", "CVE-2011-0977");
  script_bugtraq_id(46227, 47246);
  script_xref(name:"IAVA", value:"2011-A-0045-S");
  script_xref(name:"MSFT", value:"MS11-023");
  script_xref(name:"MSKB", value:"2509461");
  script_xref(name:"MSKB", value:"2509488");
  script_xref(name:"MSKB", value:"2509503");

  script_name(english:"MS11-023: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2489293)");
  script_summary(english:"Checks Office version");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Office.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Office installed on the remote host has
multiple vulnerabilities :

  - The path used for loading external libraries is not
    securely restricted.  An attacker could exploit this by
    tricking a user into opening an Office file in a
    directory that contains a malicious DLL, resulting in
    arbitrary code execution.  (CVE-2011-0107)

  - An unspecified code execution vulnerability exists in
    Office.  A remote attacker could exploit this by
    tricking a user into opening a maliciously crafted
    Office file. (CVE-2011-0977)");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-043/");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2011/ms11-023
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?99232b40");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office XP, 2003, and 2007.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("audit.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS11-023';
kbs = make_list("2509461", "2509488", "2509503");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


office_vers = hotfix_check_office_version();

arch = get_kb_item_or_exit("SMB/ARCH");
if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

x86_path = hotfix_get_commonfilesdir();
if (!x86_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');
x64_path = hotfix_get_programfilesdirx86();
if (arch == 'x64' && !x64_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Program Files (x86)');

vuln = FALSE;

# Office 2007
if (office_vers["12.0"])
{
  office_sp = get_kb_item("SMB/Office/2007/SP");
  if (!isnull(office_sp) && office_sp == 2)
  {
    if (
      hotfix_is_vulnerable(file:"Mso.dll", version:"12.0.6554.5001", min_version:'12.0.0.0', path:x86_path+"\Microsoft Shared\Office12", bulletin:bulletin, kb:"2509488") ||
      hotfix_is_vulnerable(file:"Mso.dll", arch:"x64", version:"12.0.6554.5001", min_version:'12.0.0.0', path:x64_path+"\Common Files\Microsoft Shared\Office12", bulletin:bulletin, kb:"2509488")
    ) vuln = TRUE;
  }
}
# Office 2003
if (office_vers["11.0"])
{
  office_sp = get_kb_item("SMB/Office/2003/SP");
  if (!isnull(office_sp) && office_sp == 3)
  {
    if (
      hotfix_is_vulnerable(file:"Mso.dll", version:"11.0.8333.0", min_version:'11.0.0.0', path:x86_path+"\Microsoft Shared\Office11", bulletin:bulletin, kb:"2509503") ||
      hotfix_is_vulnerable(file:"Mso.dll", arch:"x64", version:"11.0.8333.0", min_version:'11.0.0.0', path:x64_path+"\Common Files\Microsoft Shared\Office11", bulletin:bulletin, kb:"2509503")
    ) vuln = TRUE;
  }
}
# Office XP
if (office_vers["10.0"])
{
  office_sp = get_kb_item("SMB/Office/XP/SP");
  if (!isnull(office_sp) && office_sp == 3)
  {
    if (
      hotfix_is_vulnerable(file:"Mso.dll", version:"10.0.6870.0", path:x86_path+"\Microsoft Shared\Office10", bulletin:bulletin, kb:"2509461") ||
      hotfix_is_vulnerable(file:"Mso.dll", arch:"x64", version:"10.0.6870.0", path:x64_path+"\Common Files\Microsoft Shared\Office10", bulletin:bulletin, kb:"2509461")
    ) vuln = TRUE;
  }
}
if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
