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
  script_id(108976);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2018-0950");
  script_xref(name:"MSKB", value:"4018339");
  script_xref(name:"MSKB", value:"4018355");
  script_xref(name:"MSKB", value:"4018347");
  script_xref(name:"MSKB", value:"4018359");
  script_xref(name:"MSFT", value:"MS18-4018339");
  script_xref(name:"MSFT", value:"MS18-4018355");
  script_xref(name:"MSFT", value:"MS18-4018347");
  script_xref(name:"MSFT", value:"MS18-4018359");

  script_name(english:"Security Updates for Microsoft Word Products (April 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Word Products are affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Word Products are missing security updates. It is,
therefore, affected by an information disclosure vulnerability when
Office renders Rich Text Format (RTF) email messages containing OLE
objects when a message is opened or previewed. This vulnerability
could potentially result in the disclosure of sensitive information
to a malicious site.

The security update addresses the vulnerability by correcting how
Office processes OLE objects.");
  # https://support.microsoft.com/en-us/help/4018355/description-of-the-security-update-for-word-2007-april-10-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9236b3d");
  # https://support.microsoft.com/en-us/help/4018359/description-of-the-security-update-for-word-2010-april-10-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca11752e");
  # https://support.microsoft.com/en-us/help/4018347/description-of-the-security-update-for-word-2013-april-10-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1213962f");
  # https://support.microsoft.com/en-us/help/4018339/description-of-the-security-update-for-word-2016-april-10-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?124b2a7c");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB4018339
  -KB4018355
  -KB4018347
  -KB4018359");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0950");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/10");

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

global_var vuln;

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS18-04";
kbs = make_list(
  '4018355', # Word 2007 SP3
  '4018359', # Word 2010 SP2
  '4018347', # Word 2013 SP1
  '4018339'  # Word 2016
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Word 2007, 2010, 2013, 2016
######################################################################
function perform_word_checks()
{
  local_var word_checks, kb16;

  kb16 = "4018339";
  word_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6787.5000", "kb", "4018355"),
    "14.0", make_array("sp", 2, "version", "14.0.7197.5000", "kb", "4018359"),
    "15.0", make_array("sp", 1, "version", "15.0.5023.1000", "kb", "4018347"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4666.1000", "channel", "MSI", "kb", kb16),
      make_array("sp", 0, "version", "16.0.8431.2242", "channel", "Deferred", "channel_version", "1708", "kb", kb16),
      make_array("sp", 0, "version", "16.0.8201.2272", "channel", "Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.9126.2152", "channel", "First Release for Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.9126.2152", "channel", "Current", "kb", kb16)
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
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
