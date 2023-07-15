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
  script_id(117426);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-8430");
  script_bugtraq_id(105212);
  script_xref(name:"MSKB", value:"4032246");
  script_xref(name:"MSKB", value:"4092447");
  script_xref(name:"MSFT", value:"MS18-4032246");
  script_xref(name:"MSFT", value:"MS18-4092447");

  script_name(english:"Security Updates for Microsoft Word Products (September 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Word Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Word Products are missing a security update.
It is, therefore, affected by the following vulnerability :

  - A remote code execution vulnerability exists in
    Microsoft Word if a user opens a specially crafted PDF
    file. An attacker who successfully exploited the
    vulnerability could cause arbitrary code to execute in
    the context of the current user.  (CVE-2018-8430)");
  # https://support.microsoft.com/en-us/help/4032246/description-of-the-security-update-for-word-2013-september-11-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?887bf8bc");
  # https://support.microsoft.com/en-us/help/4092447/description-of-the-security-update-for-word-2016-september-11-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?06a8059c");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4032246
  -KB4092447");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8430");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
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
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS18-09";
kbs = make_list(
  '4032246', # Word 2013 SP1
  '4092447'  # Word 2016
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

port = kb_smb_transport();

######################################################################
# Word 2013, 2016
######################################################################

kb16 = "4092447";
word_checks = make_array(
  "15.0", make_array("sp", 1, "version", "15.0.5067.1000", "kb", "4032246"),
  "16.0", make_nested_list(
    make_array("sp", 0, "version", "16.0.4744.1000", "channel", "MSI", "kb", kb16)
#    make_array("sp", 0, "version", "16.0.8431.2242", "channel", "Deferred", "channel_version", "1708", "kb", kb16),
#    make_array("sp", 0, "version", "16.0.8201.2272", "channel", "Deferred", "kb", kb16),
#    make_array("sp", 0, "version", "16.0.9126.2152", "channel", "First Release for Deferred", "kb", kb16),
#    make_array("sp", 0, "version", "16.0.9126.2152", "channel", "Current", "kb", kb16)
  )
);


if (hotfix_check_office_product(product:"Word", checks:word_checks, bulletin:bulletin))
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
