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
  script_id(108969);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id(
    "CVE-2018-0920",
    "CVE-2018-1011",
    "CVE-2018-1027",
    "CVE-2018-1029"
  );
  script_xref(name:"MSKB", value:"4018353");
  script_xref(name:"MSKB", value:"4018350");
  script_xref(name:"MSKB", value:"4018337");
  script_xref(name:"MSKB", value:"4018362");
  script_xref(name:"MSFT", value:"MS18-4018353");
  script_xref(name:"MSFT", value:"MS18-4018350");
  script_xref(name:"MSFT", value:"MS18-4018337");
  script_xref(name:"MSFT", value:"MS18-4018362");

  script_name(english:"Security Updates for Microsoft Excel Products (April 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Excel Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Excel Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Excel software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-0920, CVE-2018-1011,
    CVE-2018-1027, CVE-2018-1029)");
  # https://support.microsoft.com/en-us/help/4018353/description-of-the-security-update-for-excel-2007-april-10-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52e564f2");
  # https://support.microsoft.com/en-us/help/4018350/description-of-the-security-update-for-excel-2013-april-10-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb3f7bea");
  # https://support.microsoft.com/en-us/help/4018337/description-of-the-security-update-for-excel-2016-april-10-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?839dd676");
  # https://support.microsoft.com/en-us/help/4018362/description-of-the-security-update-for-excel-2010-april-10-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4de9b158");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4018353
  -KB4018350
  -KB4018337
  -KB4018362");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1029");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
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
include("install_func.inc");

global_var vuln;

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS18-04";
kbs = make_list(
  '4018353', # 2007 SP3
  '4018362', # 2010 SP2
  '4018350', # 2013 SP1
  '4018337'  # 2016
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Excel 2007, 2010, 2013, 2016
######################################################################
kb16 = "4018337";
excel_checks = make_array(
  "12.0", make_array("sp", 3, "version", "12.0.6787.5000", "kb", "4018353"),
  "14.0", make_array("sp", 2, "version", "14.0.7197.5000", "kb", "4018362"),
  "15.0", make_array("sp", 1, "version", "15.0.5023.1000", "kb", "4018350"),
  "16.0", make_nested_list(
    make_array("sp", 0, "version", "16.0.4678.1000", "channel", "MSI", "kb", kb16), # KB Version
    make_array("sp", 0, "version", "16.0.8201.2272", "channel", "Deferred", "kb", kb16),
    make_array("sp", 0, "version", "16.0.8431.2242", "channel", "Deferred", "channel_version", "1708", "kb", kb16), # Semi-Annual Channel
    make_array("sp", 0, "version", "16.0.9126.2152", "channel", "First Release for Deferred", "kb", kb16), # Semi-Annual Channel (Targeted)
    make_array("sp", 0, "version", "16.0.9126.2152", "channel", "Current", "kb", kb16) # Monthly Channel
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
