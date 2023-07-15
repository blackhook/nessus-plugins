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
  script_id(118016);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id("CVE-2018-8504");
  script_xref(name:"MSKB", value:"4092439");
  script_xref(name:"MSKB", value:"4461457");
  script_xref(name:"MSKB", value:"4461449");
  script_xref(name:"MSFT", value:"MS18-4092439");
  script_xref(name:"MSFT", value:"MS18-4461457");
  script_xref(name:"MSFT", value:"MS18-4461449");

  script_name(english:"Security Updates for Microsoft Word Products (October 2018)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Word Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Word Products are missing a security update.
It is, therefore, affected by the following vulnerability :

  - A remote code execution vulnerability exists in
    Microsoft Word software when the software fails to
    properly handle objects in Protected View. An attacker
    who successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-8504)");
  # https://support.microsoft.com/en-us/help/4092439/description-of-the-security-update-for-word-2010-october-9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08e23f43");
  # https://support.microsoft.com/en-us/help/4461457/description-of-the-security-update-for-word-2013-october-9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ecf31700");
  # https://support.microsoft.com/en-us/help/4461449/description-of-the-security-update-for-word-2016-october-9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa70a7f6");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4092439
  -KB4461457
  -KB4461449");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8504");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS18-10";
kbs = make_list(
  '4092439', # Word 2010
  '4461457', # Word 2013
  '4461449'  # Word 2016
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Word 2010, 2013, 2016
######################################################################
function perform_word_checks()
{
  local_var word_checks, kb16;

  kb16 = "4461449";
  word_checks = make_array(
    "14.0", make_array("sp", 2, "version", "14.0.7214.5000", "kb", "4092439"),
    "15.0", make_array("sp", 1, "version", "15.0.5075.1001", "kb", "4461457"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4756.1000", "channel", "MSI", "kb", kb16)
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
