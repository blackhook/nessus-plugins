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
  script_id(111008);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-8281");
  script_xref(name:"MSKB", value:"4011202");
  script_xref(name:"MSKB", value:"4032214");
  script_xref(name:"MSFT", value:"MS18-4011202");
  script_xref(name:"MSFT", value:"MS18-4032214");

  script_name(english:"Security Updates for Microsoft Office Viewer Products / Office Compatibility Products (July 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Office software when the software fails
    to properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user.
    If the current user is logged on with administrative
    user rights, an attacker could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights. (CVE-2018-8281)");
  # https://support.microsoft.com/en-us/help/4011202/description-of-the-security-update-for-microsoft-office-viewers-and-of
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eba65869");
  # https://support.microsoft.com/en-us/help/4032214/description-of-the-security-update-for-word-viewer-july-10-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52dcdd5a");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4011202
  -KB4032214");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8281");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS18-07";
kbs = make_list(
  '4011202', # Office Compatibility Pack Service Pack 3 - Excel Viewer, PowerPoint Viewer
  '4032214'  # Office Word Viewer
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Excel Viewer
######################################################################
function perform_excel_viewer_checks()
{
  var install, installs, path, prod, common_path;
  prod = "Microsoft Excel/PowerPoint Viewer and Office Compatibility Products";
  
  installs = get_kb_list("SMB/Office/ExcelViewer/*/ProductPath");
  foreach install (keys(installs))
  {
    common_path = installs[install];
    common_path = ereg_replace(pattern:"^([A-Za-z]:.*)\\Microsoft Office.*", replace:"\1\Common Files", string:common_path);

    path = hotfix_append_path(
      path  : common_path,
      value : "Microsoft Shared\Office12"
    );

    if (hotfix_check_fversion(file:"ogl.dll", version:"12.0.6801.5000", path:path, kb:"4011202", product:prod) == HCF_OLDER)
      vuln = TRUE;
  }
}

######################################################################
# Word Viewer
######################################################################
function perform_word_viewer_checks()
{
  var install, installs, path, prod;
  prod = "Microsoft Word Viewer";

  installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
  foreach install (keys(installs))
  {
    path = installs[install];
    path = ereg_replace(pattern:"^([A-Za-z]:.*)\\[wW]ordview.exe", replace:"\1", string:path);

    if (hotfix_check_fversion(file:"gdiplus.dll", version:"11.0.8449.0", path:path, kb:"4032214", product:prod) == HCF_OLDER)
      vuln = TRUE;
  }
}


######################################################################
# MAIN
######################################################################
perform_excel_viewer_checks();
perform_word_viewer_checks();

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
