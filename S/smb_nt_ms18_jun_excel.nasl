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
  script_id(110492);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-8246");
  script_xref(name:"MSKB", value:"4022191");
  script_xref(name:"MSKB", value:"4022209");
  script_xref(name:"MSKB", value:"4022174");
  script_xref(name:"MSFT", value:"MS18-4022191");
  script_xref(name:"MSFT", value:"MS18-4022209");
  script_xref(name:"MSFT", value:"MS18-4022174");

  script_name(english:"Security Updates for Microsoft Excel Products (June 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Excel Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Excel Products are missing a security update.
It is, therefore, affected by the following vulnerability :

  - An information disclosure vulnerability exists when
    Microsoft Excel improperly discloses the contents of its
    memory. An attacker who exploited the vulnerability
    could use the information to compromise the users
    computer or data.  (CVE-2018-8246)");
  # https://support.microsoft.com/en-us/help/4022191/description-of-the-security-update-for-excel-2013-june-12-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b7ec5ad");
  # https://support.microsoft.com/en-us/help/4022209/description-of-the-security-update-for-excel-2010-june-12-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4de92d3e");
  # https://support.microsoft.com/en-us/help/4022174/description-of-the-security-update-for-excel-2016-june-12-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d92f490a");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4022191
  -KB4022209
  -KB4022174");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8246");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
include("install_func.inc");

global_var vuln;

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS18-06";
kbs = make_list(
  '4022209', # 2010
  '4022191', # 2013
  '4022174'  # 2016
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Excel 2010, 2013, 2016
######################################################################
excel_checks = make_array(
  "14.0", make_array("sp", 2, "version", "14.0.7210.5000", "kb", "4022209"),
  "15.0", make_array("sp", 1, "version", "15.0.5041.1000", "kb", "4022191"),
  "16.0", make_array("sp", 0, "version", "16.0.4705.1000", "kb", "4022174")
  );

if (hotfix_check_office_product(product:"Excel", checks:excel_checks, bulletin:bulletin))
  vuln = TRUE;

if (vuln)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
