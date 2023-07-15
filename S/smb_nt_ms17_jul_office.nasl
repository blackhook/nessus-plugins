#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(101371);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/28");

  script_cve_id(
    "CVE-2017-0243",
    "CVE-2017-8501",
    "CVE-2017-8502",
    "CVE-2017-8570"
  );
  script_bugtraq_id(
    99441,
    99442,
    99445,
    99446
  );
  script_xref(name:"MSKB", value:"2880514");
  script_xref(name:"MSKB", value:"3191833");
  script_xref(name:"MSKB", value:"3191894");
  script_xref(name:"MSKB", value:"3191897");
  script_xref(name:"MSKB", value:"3191907");
  script_xref(name:"MSKB", value:"3203468");
  script_xref(name:"MSKB", value:"3203477");
  script_xref(name:"MSKB", value:"3213537");
  script_xref(name:"MSKB", value:"3213545");
  script_xref(name:"MSKB", value:"3213555");
  script_xref(name:"MSKB", value:"3213624");
  script_xref(name:"MSKB", value:"3213640");
  script_xref(name:"MSFT", value:"MS17-2880514");
  script_xref(name:"MSFT", value:"MS17-3191833");
  script_xref(name:"MSFT", value:"MS17-3191894");
  script_xref(name:"MSFT", value:"MS17-3191897");
  script_xref(name:"MSFT", value:"MS17-3191907");
  script_xref(name:"MSFT", value:"MS17-3203468");
  script_xref(name:"MSFT", value:"MS17-3203477");
  script_xref(name:"MSFT", value:"MS17-3213537");
  script_xref(name:"MSFT", value:"MS17-3213545");
  script_xref(name:"MSFT", value:"MS17-3213555");
  script_xref(name:"MSFT", value:"MS17-3213624");
  script_xref(name:"MSFT", value:"MS17-3213640");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/25");

  script_name(english:"Security Update for Microsoft Office Products (July 2017)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office application, Microsoft Office Compatibility Pack,
or Microsoft Excel Viewer installed on the remote Windows host is
missing a security update. It is, therefore, affected by multiple
remote code execution vulnerabilities due to improper handling of
objects in memory. An unauthenticated, remote attacker can exploit
these vulnerabilities, by convincing a user to open a specially
crafted document or to visit a specially crafted website, to execute
arbitrary code in the context of the current user.

Note that KB2880514 for Office 2007 and KB3203468 for Office 2010 SP2
are only applicable to Office installations with the Galician language
pack installed.");
  script_set_attribute(attribute:"see_also", value:"https://portal.msrc.microsoft.com/en-us/security-guidance/summary");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office 2007,
2010, 2013, and 2016; Microsoft Excel 2007, 2010, 2013, and 2016;
Microsoft Excel Viewer 2007; and Microsoft Office Compatibility Pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8570");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_office_compatibility_pack_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

global_var vuln;

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS17-07";
kbs = make_list(
  '2880514', # Office 2007 SP3
  '3191833', # Excel Viewer 2007 SP3
  '3191894', # Excel 2007 SP3
  '3191897', # Office Compatibility Pack SP3
  '3191907', # Excel 2010 SP2
  '3203468', # Office 2010 SP2
  '3203477', # Excel 2016
  '3213537', # Excel 2013 SP1
  '3213545', # Office 2016
  '3213555', # Office 2013 SP1
  '3213624', # Office 2010 SP2
  '3213640'  # Office 2007 SP3
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Office 2007, 2010, 2013, 2016
######################################################################
function perform_office_checks()
{
  local_var office_vers, office_sp, path, prod, file, kb;
  office_vers = hotfix_check_office_version();

  ####################################################################
  # Office 2007 SP3 Checks
  ####################################################################
  if (office_vers["12.0"])
  {
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      prod = "Microsoft Office 2007 SP3";
      path = hotfix_append_path(
        path  : hotfix_get_officecommonfilesdir(officever:"12.0"),
        value : "Microsoft Shared\Office12"
      );
      if (hotfix_check_fversion(file:"mso.dll", version:"12.0.6772.5000", path:path, kb:"3213640", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }

  ####################################################################
  # Office 2010 SP2 Checks
  ####################################################################
  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      prod = "Microsoft Office 2010 SP2";
      path = hotfix_append_path(
        path  : hotfix_get_officecommonfilesdir(officever:"14.0"),
        value : "Microsoft Shared\Office14"
      );
      if (hotfix_check_fversion(file:"mso.dll", version:"14.0.7184.5000", path:path, kb:"3213624", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }

  ####################################################################
  # Office 2013 SP1 Checks
  ####################################################################
  if (office_vers["15.0"])
  {
    office_sp = get_kb_item("SMB/Office/2013/SP");
    if (!isnull(office_sp) && office_sp == 1)
    {
      prod = "Microsoft Office 2013 SP1";
      path = hotfix_append_path(
        path  : hotfix_get_officecommonfilesdir(officever:"15.0"),
        value : "Microsoft Shared\Office15"
      );
      if (hotfix_check_fversion(file:"mso.dll", version:"15.0.4945.1001", path:path, kb:"3213555", bulletin:bulletin, product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }

  ####################################################################
  # Office 2016 Checks
  ####################################################################
  if (office_vers["16.0"])
  {
    office_sp = get_kb_item("SMB/Office/2016/SP");
    if (!isnull(office_sp) && office_sp == 0)
    {
      prod = "Microsoft Office 2016";
      path = hotfix_append_path(
        path  : hotfix_get_officecommonfilesdir(officever:"16.0"),
        value : "Microsoft Shared\Office16"
      );
      kb   = "3213545";
      file = "mso30win32client.dll";
      if (
        hotfix_check_fversion(file:file, version:"16.0.4561.1002", channel:"MSI", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.7329.1062", channel:"Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.7726.1049", channel:"Deferred", channel_version:"1701", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8201.2136", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.8229.2086", channel:"Current", channel_product:"Office", path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER
      )
        vuln = TRUE;
    }
  }
}

function perform_proof_checks()
{
  var prod, path, paths;

  # The product code for Microsoft Office Proof (Galician) 2007 is
  # {90120000-001F-0456-0000-0000000FF1CE}
  var proof_gl_es_2007_ver = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{90120000-001F-0456-0000-0000000FF1CE}/DisplayVersion");

  # The product codes for Microsoft Office Proof (Galician) 2010 are
  # {90140000-001F-0456-0000-0000000FF1CE} (x86)
  # {90140000-001F-0456-1000-0000000FF1CE} (x64)
  var proof_gl_es_2010_x86_ver = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{90140000-001F-0456-0000-0000000FF1CE}/DisplayVersion");
  var proof_gl_es_2010_x64_ver = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{90140000-001F-0456-1000-0000000FF1CE}/DisplayVersion");

  if(isnull(proof_gl_es_2007_ver) && isnull(proof_gl_es_2010_x86_ver) &&
     isnull(proof_gl_es_2010_x64_ver))
    return NULL;

  ####################################################################
  # Microsoft Office Proof (Galician) 2007
  ####################################################################
  # KB2880514 requires product version 12.0.6612.1000 (SP3)
  if(!isnull(proof_gl_es_2007_ver) && proof_gl_es_2007_ver == "12.0.6612.1000")
  {
    prod = "Microsoft Office Proof 2007 SP3";
    path = hotfix_append_path(
             path  : hotfix_get_officecommonfilesdir(officever:"12.0"),
             value : "\Microsoft Shared\PROOF"
    );
    if (hotfix_check_fversion(file:"mssp3gl.dll", version:"15.0.4569.1503", path:path, kb:"2880514", bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
  }

  ####################################################################
  # Microsoft Office Proof (Galician) 2010
  ####################################################################
  # KB 3203468 requires product version 14.0.7015.1000 (SP2)
  if(
      ( !isnull(proof_gl_es_2010_x86_ver) &&
        proof_gl_es_2010_x86_ver == "14.0.7015.1000" ) ||
      ( !isnull(proof_gl_es_2010_x64_ver) &&
        proof_gl_es_2010_x64_ver == "14.0.7015.1000" )
  )
  {
    # The PROOF folder is in the Microsoft Office folder for 2010
    # Proofing tools can be installed with an Office program, Visio,
    # or Project, so check all unique Office paths
    prod = "Microsoft Office Proof 2010 SP2";
    paths = get_kb_list('SMB/Office/*/14.0/Path');
    if(!isnull(paths))
    {
      paths = list_uniq(make_list(paths));
      foreach path (paths)
      {
        path = hotfix_append_path(
                 path  : path,
                 value : "\PROOF"
        );
        if (hotfix_check_fversion(file:"mssp3gl.dll", version:"15.0.4569.1503", path:path, kb:"3203468", bulletin:bulletin, product:prod) == HCF_OLDER)
          vuln = TRUE;
      }
    }
  }
}

######################################################################
# Excel 2007, 2010, 2013, 2016
######################################################################
function perform_excel_checks()
{
  local_var excel_checks, kb16;

  kb16 = "3203477";
  excel_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6771.5000", "kb", "3191894"),
    "14.0", make_array("sp", 2, "version", "14.0.7183.5000", "kb", "3191907"),
    "15.0", make_array("sp", 1, "version", "15.0.4945.1000", "kb", "3213537"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4561.1000", "channel", "MSI", "kb", kb16),
      make_array("sp", 0, "version", "16.0.7369.2151", "channel", "Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.7766.2096", "channel", "Deferred", "channel_version", "1701", "kb", kb16),
      make_array("sp", 0, "version", "16.0.8201.2136", "channel", "First Release for Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.8229.2086", "channel", "Current", "kb", kb16)
    )
  );
  if (hotfix_check_office_product(product:"Excel", checks:excel_checks, bulletin:bulletin))
    vuln = TRUE;
}

######################################################################
# Compatibility Pack
######################################################################
function perform_comppack_checks()
{
  local_var excel_compat_checks;

  ####################################################################
  # Excel Compatibility Pack
  ####################################################################
  excel_compat_checks = make_array(
    "12.0", make_array("version", "12.0.6771.5000", "kb", "3191897")
  );
  if (hotfix_check_office_product(product:"ExcelCnv", display_name:"Office Compatibility Pack SP3", checks:excel_compat_checks, bulletin:bulletin))
    vuln = TRUE;
}

######################################################################
# Excel Viewer
######################################################################
function perform_viewer_checks()
{
  var excel_vwr_checks = make_array(
    "12.0", make_array("version", "12.0.6771.5000", "kb", "3191833")
  );
  if (hotfix_check_office_product(product:"ExcelViewer", display_name:"Excel Viewer", checks:excel_vwr_checks, bulletin:bulletin))
    vuln = TRUE;
}

######################################################################
# MAIN
######################################################################
perform_office_checks();
perform_proof_checks();
perform_excel_checks();
perform_comppack_checks();
perform_viewer_checks();

if (vuln)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
