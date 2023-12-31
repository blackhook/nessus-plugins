#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(39343);
  script_version("1.34");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/08");

  script_cve_id(
    "CVE-2009-0549",
    "CVE-2009-0557",
    "CVE-2009-0558",
    "CVE-2009-0559",
    "CVE-2009-0560",
    "CVE-2009-0561",
    "CVE-2009-1134"
  );
  script_bugtraq_id(
    35215,
    35241,
    35242,
    35243,
    35244,
    35245,
    35246
  );
  script_xref(name:"MSFT", value:"MS09-021");
  script_xref(name:"MSKB", value:"969679");
  script_xref(name:"MSKB", value:"969680");
  script_xref(name:"MSKB", value:"969681");
  script_xref(name:"MSKB", value:"969682");
  script_xref(name:"MSKB", value:"969683");
  script_xref(name:"MSKB", value:"969685");
  script_xref(name:"MSKB", value:"969686");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"MS09-021: Vulnerabilities in Microsoft Office Excel Could Allow Remote Code Execution (969462)");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary code on the remote Windows host
using Microsoft Excel.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Excel / Excel Viewer /
2007 Microsoft Office system or the Microsoft Office Compatibility
Pack that is affected by several buffer overflow and memory corruption
vulnerabilities.  If an attacker can trick a user on the affected host
into opening a specially crafted Excel file, any of these issues could
be leveraged to run arbitrary code on the host subject to the user's
privileges.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2009/ms09-021");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-09-040/");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Excel 2000, 2002, 2003,
and 2007, Excel Viewer and Excel Viewer 2003 as well as the 2007
Microsoft Office system and the Microsoft Office Compatibility Pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-1134");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(94, 189, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2022 Tenable Network Security, Inc.");

  script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS09-021';
kbs = make_list("969679", "969680", "969681", "969682", "969683", "969685", "969686");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


info = "";
vuln = 0;
kb = "";
# Excel.
installs = get_kb_list("SMB/Office/Excel/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/Excel/' - '/ProductPath';
    path = installs[install];

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # Excel 2007.
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6504 ||
        (ver[2] == 6504 && ver[3] < 5001)
      )
    )
    {
      office_sp = get_kb_item("SMB/Office/2007/SP");
      if (!isnull(office_sp) && (office_sp == 1 || office_sp == 2))
      {
        vuln++;
        kb = "969682";
        info =
          '\n  Product           : Excel 2007' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 12.0.6504.5001\n';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }
    # Excel 2003.
    else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8307)
    {
      office_sp = get_kb_item("SMB/Office/2003/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        vuln++;
        kb = "969681";
        info =
          '\n  Product           : Excel 2003' +
          '\n  File              : ' + path +
          '\n  Installed version : ' +version +
          '\n  Fixed version     : 11.0.8307.0\n';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }
    # Excel 2002.
    else if (ver[0] == 10 && ver[1] == 0 && ver[2] < 6854)
    {
      office_sp = get_kb_item("SMB/Office/XP/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        vuln++;
        kb = "969680";
        info =
          '\n  Product           : Excel 2002' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 10.0.6854.0\n';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }
    # Excel 2000.
    else if (ver[0] == 9 && ver[1] == 0 && ver[2] == 0 && ver[3] < 8979)
    {
      office_sp = get_kb_item("SMB/Office/2000/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        vuln++;
        kb = "969683";
        info =
          '\n  Product           : Excel 2000' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 9.0.0.8979\n';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }
  }
}


# Excel Viewer.
installs = get_kb_list("SMB/Office/ExcelViewer/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/ExcelViewer/' - '/ProductPath';
    path = installs[install];

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # Excel Viewer.
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6504 ||
        (ver[2] == 6504 && ver[3] < 5000)
      )
    )
    {
      vuln++;
      kb = "969686";
      info =
        '\n  Product           : Excel Viewer' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6504.5000\n';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
    }
    # Excel Viewer 2003.
    else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8307)
    {
      vuln++;
      kb = "969685";
      info =
        '\n  Product           : Excel 2003' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 11.0.8307.0\n';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
    }
  }
}


# 2007 Microsoft Office system and the Microsoft Office Compatibility Pack.
installs = get_kb_list("SMB/Office/ExcelCnv/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/ExcelCnv/' - '/ProductPath';
    path = installs[install];

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # 2007 Office system and the Office Compatibility Pack.
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6504 ||
        (ver[2] == 6504 && ver[3] < 5001)
      )
    )
    {
      vuln++;
      kb = "969679";
      info =
        '\n  Product           : 2007 Office system and the Office Compatibility Pack' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6504.5001\n';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
    }
  }
}
if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
