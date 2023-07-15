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
  script_id(118014);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_xref(name:"MSKB", value:"4092477");
  script_xref(name:"MSKB", value:"4461440");
  script_xref(name:"MSKB", value:"4227170");
  script_xref(name:"MSFT", value:"MS18-4092477");
  script_xref(name:"MSFT", value:"MS18-4461440");
  script_xref(name:"MSFT", value:"MS18-4227170");

  script_name(english:"Security Updates for Outlook (October 2018)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Outlook application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Outlook application installed on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities including a remote code execution
vulnerability requiring user interaction. See Microsoft Security
Advisory ADV180026 for more information.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV180026
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a01db1c3");
  # https://support.microsoft.com/en-us/help/4092477/description-of-the-security-update-for-outlook-2013-october-9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8fd9e29");
  # https://support.microsoft.com/en-us/help/4461440/description-of-the-security-update-for-outlook-2016-october-9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78c94412");
  # https://support.microsoft.com/en-us/help/4227170/description-of-the-security-update-for-outlook-2010-october-9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1851023");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this
issue:
  -KB4092477
  -KB4461440
  -KB4227170");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS18-10";
kbs = make_list(
  '4227170', # 2010 SP2 / 14.0
  '4092477', # 2013 SP1 / 15.0
  '4461440'  # 2016 / 16.0
);
kb16 = '4461440';

if (get_kb_item("Host/patch_management_checks")) 
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

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
    "14.0", make_array("version", "14.0.7214.5000", "kb", "4227170"), # 2010
    "15.0", make_array("version", "15.0.5075.1001", "kb", "4092477"), # 2013
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4756.1001", "channel", "MSI", "kb", "4461440")
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
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

