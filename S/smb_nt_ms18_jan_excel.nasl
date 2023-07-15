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
  script_id(105694);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2018-0796");
  script_bugtraq_id(102372);

  script_xref(name:"MSKB", value:"4011602");
  script_xref(name:"MSKB", value:"4011627");
  script_xref(name:"MSKB", value:"4011639");
  script_xref(name:"MSKB", value:"4011660");
  script_xref(name:"MSFT", value:"MS17-4011602");
  script_xref(name:"MSFT", value:"MS17-4011627");
  script_xref(name:"MSFT", value:"MS17-4011639");
  script_xref(name:"MSFT", value:"MS17-4011660");
  script_xref(name:"IAVA", value:"2018-A-0009-S");

  script_name(english:"Security Updates for Microsoft Excel Products (January 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Excel Products are affected by a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Excel Products are missing a security update.
It is, therefore, affected by the following vulnerability :

  - A remote code execution vulnerability exists in
    Microsoft Office software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights. (CVE-2018-0796)");
  # https://support.microsoft.com/en-us/help/4011602/descriptionofthesecurityupdateforexcel2007january9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01001d0d");
  # https://support.microsoft.com/en-us/help/4011660/descriptionofthesecurityupdateforexcel2010january9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5dd4608");
  # https://support.microsoft.com/en-us/help/4011639/descriptionofthesecurityupdateforexcel2013january9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?06c16d3c");
  # https://support.microsoft.com/en-us/help/4011627/descriptionofthesecurityupdateforexcel2016january9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c624d784");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB4011602
  -KB4011627
  -KB4011639
  -KB4011660");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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

bulletin = "MS18-01";
kbs = make_list(
  '4011602', # Excel 2007 SP3
#  '4011627', # Excel 2016
  '4011639', # Excel 2013 SP1
  '4011660'  # Excel 2010 SP2
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();


######################################################################
# Excel 2007, 2010, 2013, 2016
######################################################################
kb16 = "4011627";
excel_checks = make_array(
  "12.0", make_array("sp", 3, "version", "12.0.6784.5000", "kb", "4011602"),
  "14.0", make_array("sp", 2, "version", "14.0.7192.5000", "kb", "4011660"),
  "15.0", make_array("sp", 1, "version", "15.0.4997.1000", "kb", "4011639"),
  "16.0", make_nested_list(
    make_array("sp", 0, "version", "16.0.4639.1000", "channel", "MSI", "kb", kb16),
    make_array("sp", 0, "version", "16.0.8201.2217", "channel", "Deferred", "kb", kb16),
    make_array("sp", 0, "version", "16.0.8431.2153", "channel", "Deferred", "channel_version", "1708", "kb", kb16),
    make_array("sp", 0, "version", "16.0.8431.2153", "channel", "First Release for Deferred", "kb", kb16),
    make_array("sp", 0, "version", "16.0.8730.2175", "channel", "Current", "kb", kb16)
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
