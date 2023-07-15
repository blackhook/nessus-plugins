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
  script_id(110994);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-8310");
  script_bugtraq_id(104615);
  script_xref(name:"MSKB", value:"4022218");
  script_xref(name:"MSKB", value:"4022224");
  script_xref(name:"MSKB", value:"4022202");
  script_xref(name:"MSFT", value:"MS18-4022218");
  script_xref(name:"MSFT", value:"MS18-4022224");
  script_xref(name:"MSFT", value:"MS18-4022202");

  script_name(english:"Security Updates for Microsoft Word Products (July 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Word Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Word Products are missing a security update.
It is, therefore, affected by the following vulnerability :

  - A tampering vulnerability exists when Microsoft Outlook
    does not properly handle specific attachment types when
    rendering HTML emails. An attacker could exploit the
    vulnerability by sending a specially crafted email and
    attachment to a victim, or by hosting a malicious .eml
    file on a web server. The attacker who successfully
    exploited the vulnerability could then embed untrusted
    TrueType fonts in the body of an email. This behavior
    could be combined with other exploits to further
    compromise a user's system. The security update
    addresses the vulnerability by correcting how Microsoft
    Outlook handles attachments. (CVE-2018-8310)");
  # https://support.microsoft.com/en-us/help/4022218/description-of-the-security-update-for-word-2016-july-10-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38466f10");
  # https://support.microsoft.com/en-us/help/4022224/description-of-the-security-update-for-word-2013-july-10-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5386f78");
  # https://support.microsoft.com/en-us/help/4022202/description-of-the-security-update-for-word-2010-july-10-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3c4a554");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4022218
  -KB4022224
  -KB4022202");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8310");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/10");

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

bulletin = "MS18-07";
kbs = make_list(
  '4022202', # Word 2010 SP2
  '4022224', # Word 2013 SP1
  '4022218'  # Word 2016
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Word 2010, 2013, 2016
######################################################################
function perform_word_checks()
{
  local_var word_checks, kb16;

  kb16 = "4022218";
  word_checks = make_array(
    "14.0", make_array("sp", 2, "version", "14.0.7211.5000", "kb", "4022202"),
    "15.0", make_array("sp", 1, "version", "15.0.5049.1000", "kb", "4022224"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4717.1000", "channel", "MSI", "kb", kb16),
      make_array("sp", 0, "version", "16.0.9126.2259", "channel", "Deferred", "channel_version", "1803", "kb", kb16),
      make_array("sp", 0, "version", "16.0.8431.2280", "channel", "Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.9126.2259", "channel", "First Release for Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.10228.20104", "channel", "Current", "kb", kb16)
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
