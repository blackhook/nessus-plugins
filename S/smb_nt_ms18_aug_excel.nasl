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
  script_id(111694);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-8375", "CVE-2018-8379", "CVE-2018-8382");
  script_xref(name:"MSKB", value:"4032223");
  script_xref(name:"MSKB", value:"4032229");
  script_xref(name:"MSKB", value:"4032241");
  script_xref(name:"MSFT", value:"MS18-4032223");
  script_xref(name:"MSFT", value:"MS18-4032229");
  script_xref(name:"MSFT", value:"MS18-4032241");

  script_name(english:"Security Updates for Microsoft Excel Products (August 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Excel Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Excel Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists when
    Microsoft Excel improperly discloses the contents of its
    memory. An attacker who exploited the vulnerability
    could use the information to compromise the users
    computer or data.  (CVE-2018-8382)

  - A remote code execution vulnerability exists in
    Microsoft Excel software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-8375, CVE-2018-8379)");
  # https://support.microsoft.com/en-us/help/4032223/description-of-the-security-update-for-excel-2010-august-14-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f7e98db4");
  # https://support.microsoft.com/en-us/help/4032229/description-of-the-security-update-for-excel-2016-august-14-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?071d9591");
  # https://support.microsoft.com/en-us/help/4032241/description-of-the-security-update-for-excel-2013-august-14-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89b49727");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4032223
  -KB4032229
  -KB4032241");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8375");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/14");

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

bulletin = "MS18-08";
kbs = make_list(
  '4032223', # 2010
  '4032241', # 2013
  '4032229'  # 2016
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Excel 2010, 2013, 2016
######################################################################
excel_checks = make_array(
  "14.0", make_array("sp", 2, "version", "14.0.7212.5000", "kb", "4032223"),
  "15.0", make_array("sp", 1, "version", "15.0.5059.1000", "kb", "4032241"),
  "16.0", make_array("sp", 0, "version", "16.0.4732.1000", "kb", "4032229")
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
