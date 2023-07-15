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
  script_id(106803);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id("CVE-2018-0841");
  script_xref(name:"IAVA", value:"2018-A-0051-S");

  script_name(english:"Security Updates for Microsoft Excel Products (February 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Excel Products are affected by a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Excel Products are missing a security update.
It is, therefore, affected by the following vulnerability :

  - A remote code execution vulnerability exists in Microsoft Excel
    software when the software fails to properly handle objects in
    memory. An attacker who successfully exploited the vulnerability
    could run arbitrary code in the context of the current user. If
    the current user is logged on with administrative user rights, an
    attacker could take control of the affected system. An attacker
    could then install programs; view, change, or delete data; or
    create new accounts with full user rights. Users whose accounts
    are configured to have fewer user rights on the system could be
    less impacted than users who operate with administrative user
    rights. (CVE-2018-0841)");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0841
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5cadf2c9");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a security update to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2020 Tenable Network Security, Inc.");

  script_dependencies(
    "office_installed.nasl",
    "microsoft_office_compatibility_pack_installed.nbin",
    "smb_hotfixes.nasl",
    "ms_bulletin_checks_possible.nasl");
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

bulletin = "MS18-02";

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Excel 2016
######################################################################
kb16 = "n/a"; # required for hotfix_add_report() call in hotfix_check_office_products()
excel_checks = make_array(
  "16.0", make_nested_list(
    make_array("sp", 0, "version", "16.0.8201.2258", "channel", "Deferred", "kb", kb16),
    make_array("sp", 0, "version", "16.0.8431.2215", "channel", "Deferred", "channel_version", "1708", "kb", kb16),
    make_array("sp", 0, "version", "16.0.8431.2215", "channel", "First Release for Deferred", "kb", kb16),
    make_array("sp", 0, "version", "16.0.9001.2171", "channel", "Current", "kb", kb16)
  )
);
if (hotfix_check_office_product(product:"Excel", checks:excel_checks, bulletin:bulletin))
  vuln = TRUE;

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
