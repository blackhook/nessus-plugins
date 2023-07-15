#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(105192);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/20");
  script_xref(name:"MSKB", value:"4011590");
  script_xref(name:"MSKB", value:"4011608");
  script_xref(name:"MSKB", value:"4011614");
  script_xref(name:"MSKB", value:"4011575");
  script_xref(name:"MSFT", value:"MS17-4011590");
  script_xref(name:"MSFT", value:"MS17-4011608");
  script_xref(name:"MSFT", value:"MS17-4011614");
  script_xref(name:"MSFT", value:"MS17-4011575");
  script_xref(name:"IAVA", value:"2017-A-0363-S");

  script_name(english:"Security Updates for Microsoft Word Products (December 2017)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Word Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Word Products are missing security updates. Microsoft
has released an update for Microsoft Office that provides enhanced
security as a defense-in-depth measure. The update disables the
Dynamic Update Exchange protocol (DDE) in all supported editions of
Microsoft Word. More information can be found in Microsoft Security
Advisory 4053440.");
  # https://support.microsoft.com/en-us/help/4011608/descriptionofthesecurityupdateforword2007december12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e17d43f2");
  # https://support.microsoft.com/en-us/help/4011614/descriptionofthesecurityupdateforword2010december12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ceb21ee");
  # https://support.microsoft.com/en-us/help/4011590/descriptionofthesecurityupdateforword2013december12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82734374");
  # https://support.microsoft.com/en-us/help/4011575/descriptionofthesecurityupdateforword2016december12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?affd3524");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV170021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?314d33a5");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB4011590
  -KB4011608
  -KB4011614
  -KB4011575");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2023 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = "MS17-12";
kbs = make_list(
  '4011608', # Word 2007 SP3
  '4011614', # Word 2010 SP2
  '4011590', # Word 2013 SP1
  '4011575'  # Word 2016
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Word 2007, 2010, 2013, 2016
######################################################################
function perform_word_checks()
{
  local_var word_checks, kb16;

  kb16 = "4011575";
  word_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6782.5000", "kb", "4011608"),
    "14.0", make_array("sp", 2, "version", "14.0.7191.5000", "kb", "4011614"),
    "15.0", make_array("sp", 1, "version", "15.0.4989.1000", "kb", "4011590"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4627.1000", "channel", "MSI", "kb", kb16),
      make_array("sp", 0, "version", "16.0.7766.2130", "channel", "Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.8201.2213", "channel", "Deferred", "channel_version", "1705", "kb", kb16),
      make_array("sp", 0, "version", "16.0.8431.2131", "channel", "First Release for Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.8730.2127", "channel", "Current", "kb", kb16)
    )
  );
  if (hotfix_check_office_product(product:"Word", checks:word_checks, bulletin:bulletin))
    vuln = TRUE;
}

######################################################################
# MAIN
######################################################################
perform_word_checks();

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
