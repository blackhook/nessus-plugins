#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(90436);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/17");

  script_cve_id(
    "CVE-2016-0122",
    "CVE-2016-0127",
    "CVE-2016-0136",
    "CVE-2016-0139"
  );
  script_bugtraq_id(
    85897,
    85901,
    85923,
    85934
  );
  script_xref(name:"MSFT", value:"MS16-042");
  script_xref(name:"MSKB", value:"3114871");
  script_xref(name:"MSKB", value:"3114888");
  script_xref(name:"MSKB", value:"3114892");
  script_xref(name:"MSKB", value:"3114895");
  script_xref(name:"MSKB", value:"3114897");
  script_xref(name:"MSKB", value:"3114898");
  script_xref(name:"MSKB", value:"3114927");
  script_xref(name:"MSKB", value:"3114934");
  script_xref(name:"MSKB", value:"3114937");
  script_xref(name:"MSKB", value:"3114947");
  script_xref(name:"MSKB", value:"3114964");
  script_xref(name:"MSKB", value:"3114982");
  script_xref(name:"MSKB", value:"3114983");
  script_xref(name:"MSKB", value:"3114987");
  script_xref(name:"MSKB", value:"3114988");
  script_xref(name:"MSKB", value:"3114990");
  script_xref(name:"MSKB", value:"3114993");
  script_xref(name:"MSKB", value:"3114994");
  script_xref(name:"IAVA", value:"2016-A-0090-S");

  script_name(english:"MS16-042: Security Update for Microsoft Office (3148775)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Office installed on the remote Windows host
is affected by multiple remote code execution vulnerabilities due to
improper handling of objects in memory. A remote attacker can exploit
these issues by convincing a user to open a specially crafted file in
Microsoft Office, resulting in the execution of arbitrary code in the
context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-042");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/3148775/ms16-042-security-update-for-microsoft-office-april-12-2016");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office 2010;
Microsoft Word 2007, 2010, 2013, and 2013 RT; Microsoft Excel 2007,
2010, 2013, 2013 RT, and 2016; Word Viewer; Excel Viewer; SharePoint
Server 2007, 2010, and 2013; Microsoft Office Compatibility Pack; and
Office Web Apps 2010 and 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0139");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_owa_installed.nbin", "microsoft_sharepoint_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

global_var bulletin, vuln;

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-042';
kbs = make_list(
  '3114871', ## SharePoint Server 2010 SP2
  '3114888', ## Excel 2010 SP2
  '3114892', ## Excel 2007 SP3
  '3114895', ## Office Compatibility Pack SP3
  '3114897', ## SharePoint Server 2007 SP3
  '3114898', ## Excel Viewer
  '3114927', ## Word Automation Services SharePoint 2013 SP1
  '3114934', ## Office Web Apps Server 2013 SP1
  '3114937', ## Word 2013 SP1
  '3114947', ## Excel 2013 SP1
  '3114964', ## Excel 2016
  '3114982', ## Office Compatibility Pack SP3
  '3114983', ## Word 2007 SP3
  '3114987', ## Word Viewer
  '3114988', ## Word Automation Services SharePoint 2010 SP2
  '3114990', ## Office 2010 SP2
  '3114993', ## Word 2010 SP2
  '3114994'  ## Office Web Apps 2010 SP2
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");
registry_init();

vuln = FALSE;

######################################################################
# Office Web Apps
######################################################################
function perform_owa_checks()
{
  local_var owa_installs, owa_install;
  local_var owa_2010_path, owa_2010_sp;
  local_var owa_2013_path, owa_2013_sp;
  local_var path;

  # Get installs of Office Web Apps
  owa_installs = get_installs(app_name:"Microsoft Office Web Apps");
  if (!empty_or_null(owa_installs))
  {
    foreach owa_install (owa_installs[1])
    {
      if (owa_install["Product"] == "2010")
      {
        owa_2010_path = owa_install["path"];
        owa_2010_sp = owa_install["SP"];
      }
      if (owa_install['Product'] == "2013")
      {
        owa_2013_path = owa_install['path'];
        owa_2013_sp = owa_install['SP'];
      }
    }
  }

  ######################################################################
  # Office Web Apps 2010 SP2
  ######################################################################
  if (owa_2010_path && (!isnull(owa_2010_sp) && owa_2010_sp == "2"))
  {
    path = hotfix_append_path(path:owa_2010_path, value:"14.0\WebServices\ConversionService\Bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7168.5000", min_version:"14.0.7015.1000", path:path, bulletin:bulletin, kb:"3114994", product:"Office Web Apps 2010") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # Office Web Apps 2013 SP1
  ######################################################################
  if (owa_2013_path && (!isnull(owa_2013_sp) && owa_2013_sp == "1"))
  {
    path = hotfix_append_path(path:owa_2013_path, value:"ExcelServicesEcs\bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"15.0.4815.1000", min_version:"15.0.4571.1500", path:path, bulletin:bulletin, kb:"3114934", product:"Office Web Apps 2013") == HCF_OLDER)
      vuln = TRUE;
  }
}

function perform_office_checks()
{
  local_var office_vers, office_sp, path;
  office_vers = hotfix_check_office_version();

  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"14.0"), value:"Microsoft Office\Office14");
      if (
        hotfix_check_fversion(file:"wwlibcxm.dll", version: "14.0.7168.5000", path:path, bulletin:bulletin, kb:"3114990", product:"Microsoft Office 2010 SP2") == HCF_OLDER
      ) vuln = TRUE;
    }
  }
}

function perform_office_product_checks()
{
  local_var checks, word_vwr_checks, vwr_checks, compat_checks, kb;

  local_var installs, install, path; # For DLL checks

  ######################################################################
  # Word Checks
  ######################################################################
  checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6747.5000", "kb", "3114983"),
    "14.0", make_array("sp", 2, "version", "14.0.7168.5000", "kb", "3114993"),
    "15.0", make_array("sp", 1, "version", "15.0.4815.1000", "kb", "3114937")
  );
  if (hotfix_check_office_product(product:"Word", checks:checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Viewer
  ######################################################################
  installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
  if(!isnull(installs))
  {
    word_vwr_checks = make_array(
      "11.0", make_array("version", "11.0.8426.0", "kb", "3114987")
    );
    if (hotfix_check_office_product(product:"WordViewer", display_name:"Word Viewer", checks:word_vwr_checks, bulletin:bulletin))
      vuln = TRUE;
  }

  ######################################################################
  # Word Compatibility pack
  ######################################################################
  installs = get_kb_list("SMB/Office/WordCnv/*/ProductPath");
  foreach install (keys(installs))
  {
    path = installs[install];
    path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe$', replace:"\1\", string:path, icase:TRUE);
    if(hotfix_check_fversion(path:path, file:"wordcnv.dll",  version:"12.0.6747.5000", kb: "3114982", bulletin:bulletin, min_version:"12.0.0.0", product:"Microsoft Office Compatibility Pack") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # Excel Compatibility pack
  ######################################################################
  compat_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6747.5000", "kb", "3114895")
  );
  if (hotfix_check_office_product(product:"ExcelCnv", display_name:"Office Compatibility Pack SP3", checks:compat_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Excel Viewer
  ######################################################################
  vwr_checks = make_array(
    "12.0", make_array("version", "12.0.6747.5000", "kb", "3114898")
  );
  if (hotfix_check_office_product(product:"ExcelViewer", display_name:"Excel Viewer", checks:vwr_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Excel Checks
  ######################################################################
  checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6747.5000", "kb", "3114892"),
    "14.0", make_array("sp", 2, "version", "14.0.7168.5000", "kb", "3114888"),
    "15.0", make_array("sp", 1, "version", "15.0.4815.1000", "kb", "3114947"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4366.1000", "kb", "3114964"),
      make_array("sp", 0, "version", "16.0.6001.1073", "channel", "Deferred", "kb", "3114964"),
      make_array("sp", 0, "version", "16.0.6741.2026", "channel", "First Release for Deferred", "kb", "3114964"),
      make_array("sp", 0, "version", "16.0.6769.2017", "channel", "Current", "kb", "3114964")
    )
  );
  if (hotfix_check_office_product(product:"Excel", checks:checks, bulletin:bulletin))
    vuln = TRUE;
}

######################################################################
# SharePoint
######################################################################
function perform_sharepoint_checks()
{
  local_var sps_2007_path, sps_2007_sp, sps_2007_edition;
  local_var sps_2013_path, sps_2013_sp, sps_2013_edition;
  local_var sps_2010_path, sps_2010_sp, sps_2010_edition;
  local_var installs, install, path, prod;

  sps_2013_path = NULL;

  installs = get_installs(app_name:"Microsoft SharePoint Server");
  foreach install (installs[1])
  {
    if (install['Product'] == "2007")
    {
      sps_2007_path = install['path'];
      sps_2007_sp = install['SP'];
      sps_2007_edition = install['Edition'];
    }
    else if (install["Product"] == "2010")
    {
      sps_2010_path = install['path'];
      sps_2010_sp = install['SP'];
      sps_2010_edition = install['Edition'];
    }
    else if (install['Product'] == "2013")
    {
      sps_2013_path = install['path'];
      sps_2013_sp = install['SP'];
      sps_2013_edition = install['Edition'];
      break;
    }
  }

  # Office Services and Web Apps
  ######################################################################
  # SharePoint Server 2007 SP3 - Excel Services
  ######################################################################
  if (sps_2007_path && sps_2007_sp == "3" && sps_2007_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2007_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"12.0.6747.5000", path:path, bulletin:bulletin, kb:"3114897", product:"Office SharePoint Server 2007 Excel Services") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2010 SP2 - Excel Services
  ######################################################################
  if (sps_2010_path && sps_2010_sp == "2" && sps_2010_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2010_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"14.0.7168.5000", path:path, bulletin:bulletin, kb:"3114871", product:"Office SharePoint Server 2010 Excel Services") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2010 SP2 - Word Automation Services
  ######################################################################
  if (sps_2010_path && sps_2010_sp == "2" && sps_2010_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2010_path, value:"WebServices\WordServer\Core");
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7168.5000", path:path, bulletin:bulletin, kb:"3114988", product:"Office SharePoint Server 2010 Word Automation Services") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2013
  ######################################################################
  if (sps_2013_path)
  {
    if (sps_2013_sp == "1")
    {
      if(sps_2013_edition == "Server")
      {
        path = hotfix_append_path(path:sps_2013_path, value:"WebServices\ConversionServices");
        if (hotfix_check_fversion(file:"sword.dll", version:"15.0.4815.1000", min_version:"15.0.0.0", path:path, bulletin:bulletin, kb:"3114927", product:"Office SharePoint Server 2013 Word Automation Services") == HCF_OLDER)
        vuln = TRUE;
      }
    }
  }
}

perform_office_checks();
perform_office_product_checks();
perform_sharepoint_checks();
perform_owa_checks();

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
  audit(AUDIT_HOST_NOT, 'affected');
}
