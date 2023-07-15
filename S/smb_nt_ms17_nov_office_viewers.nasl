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
  script_id(104559);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2017-11877", "CVE-2017-11878");
  script_bugtraq_id(101747, 101756);
  script_xref(name:"MSKB", value:"4011206");
  script_xref(name:"MSKB", value:"4011264");
  script_xref(name:"MSFT", value:"MS17-4011206");
  script_xref(name:"MSFT", value:"MS17-4011264");
  script_xref(name:"IAVA", value:"2017-A-0337-S");

  script_name(english:"Security Updates for Microsoft Office Viewer Products (November 2017)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Viewer Products are affected by multiple 
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Office software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2017-11878)

  - A security feature bypass vulnerability exists in
    Microsoft Office software by not enforcing macro
    settings on an Excel document. The security feature
    bypass by itself does not allow arbitrary code
    execution. To successfully exploit the vulnerability, an
    attacker would have to embed a control in an Excel
    worksheet that specifies a macro should be run.
    (CVE-2017-11877)");
  # https://support.microsoft.com/en-us/help/4011206/descriptionofthesecurityupdateforexcelviewer2007november14-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8cf48610");
  # https://support.microsoft.com/en-us/help/4011264/descriptionofthesecurityupdateforwordviewernovember14-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52a7be1a");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4011206
  -KB4011264");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11878");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS17-11";
kbs = make_list(
  '4011206', # Excel Viewer 2007 SP3
  '4011264'  # Office Word Viewer
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
  var excel_vwr_checks = make_array(
    "12.0", make_array("version", "12.0.6780.5000", "kb", "4011206")
  );
  if (hotfix_check_office_product(product:"ExcelViewer", display_name:"Excel Viewer", checks:excel_vwr_checks, bulletin:bulletin))
    vuln = TRUE;
}

######################################################################
# Word Viewer
######################################################################
function perform_word_viewer_checks()
{
  var word_vwr_checks = make_array(
    "11.0", make_array("version", "11.0.8445.0", "kb", "4011264")
  );
  if (hotfix_check_office_product(product:"WordViewer", display_name:"Word Viewer", checks:word_vwr_checks, bulletin:bulletin))
    vuln = TRUE;
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
