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
  script_id(111756);
  script_version("1.1");
  script_cvs_date("Date: 2018/08/15 18:17:18");

  script_xref(name:"MSKB", value:"4032222");
  script_xref(name:"MSKB", value:"4032235");
  script_xref(name:"MSKB", value:"4032240");
  script_xref(name:"MSFT", value:"MS18-4032222");
  script_xref(name:"MSFT", value:"MS18-4032235");
  script_xref(name:"MSFT", value:"MS18-4032240");

  script_name(english:"Security Updates for Outlook (August 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Outlook application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Outlook application installed on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities.
");
  # https://support.microsoft.com/en-us/help/4032222/description-of-the-security-update-for-outlook-2010-august-14-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60c26d6f");
  # https://support.microsoft.com/en-us/help/4032235/description-of-the-security-update-for-outlook-2016-august-14-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?358ccbe3");
  # https://support.microsoft.com/en-us/help/4032240/description-of-the-security-update-for-outlook-2013-august-14-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?739c8d00");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4032222
  -KB4032235
  -KB4032240");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl","ms_bulletin_checks_possible.nasl");
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

bulletin = "MS18-08";
kbs = make_list(
  '4032222', # 2010 SP2 / 14.0
  '4032240', # 2013 SP1 / 15.0
  '4032235'  # 2016     / 16.0
);
kb16 = '4032235';

if (get_kb_item("Host/patch_management_checks")) 
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_NOTE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

port = kb_smb_transport();

######################################################################
# Outlook 2010, 2013, 2016
######################################################################
function perform_outlook_checks()
{
  local_var vuln, checks, path;
  vuln = 0;
  checks = make_array(
    "14.0", make_array("version", "14.0.7212.5000", "kb", "4032222"), # 2010
    "15.0", make_array("version", "15.0.5059.1000", "kb", "4032240"), # 2013
    "16.0", make_nested_list(
      make_array("version", "16.0.4732.1000", "channel", "MSI", "kb", kb16), # 2016
      make_array("version", "16.0.10325.20118", "channel", "Current", "kb", kb16), # Monthly
      make_array("version", "16.0.9126.2275", "channel", "First Release for Deferred", "kb", kb16), # Targeted
      make_array("version", "16.0.8431.2299", "channel", "Deferred", "channel_version", "1708", "kb", kb16), # Semi-Annual
      make_array("version", "16.0.8431.2299", "channel", "Deferred", "kb", kb16) # Deferred
    )
  );
  if (hotfix_check_office_product(product:"Outlook", checks:checks, bulletin:bulletin))
    vuln += 1;

  return vuln;
}


######################################################################
# MAIN
######################################################################
vuln = perform_outlook_checks();

if (vuln)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_note();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

