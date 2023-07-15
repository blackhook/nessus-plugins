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
  script_id(110499);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-8244");
  script_xref(name:"MSKB", value:"4022205");
  script_xref(name:"MSKB", value:"4022169");
  script_xref(name:"MSKB", value:"4022160");
  script_xref(name:"MSFT", value:"MS18-4022205");
  script_xref(name:"MSFT", value:"MS18-4022169");
  script_xref(name:"MSFT", value:"MS18-4022160");

  script_name(english:"Security Updates for Outlook (June 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Outlook application installed on the remote host is
missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Outlook application installed on the remote
host is missing a security update. It is, therefore,
affected by the following vulnerability :

  - An elevation of privilege vulnerability exists when
    Microsoft Outlook does not validate attachment headers
    properly. An attacker who successfully exploited the
    vulnerability could send an email with hidden
    attachments that would be opened or executed once a
    victim clicks a link within the email. Note that this
    does not bypass attachment filters, so blocked
    attachments will still be excluded.  (CVE-2018-8244)");
  # https://support.microsoft.com/en-us/help/4022205/description-of-the-security-update-for-outlook-2010-june-12-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a742cfc");
  # https://support.microsoft.com/en-us/help/4022169/description-of-the-security-update-for-outlook-2013-june-12-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ae314ee");
  # https://support.microsoft.com/en-us/help/4022160/description-of-the-security-update-for-outlook-2016-june-12-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11615a33");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4022205
  -KB4022169
  -KB4022160");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8244");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
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

bulletin = "MS18-06";
kbs = make_list(
  '4022205', # 2010 SP2 / 14.0
  '4022169', # 2013 SP1 / 15.0
  '4022160'  # 2016     / 16.0
);
kb16 = '4022160';

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

port = kb_smb_transport();

######################################################################
# Outlook 2007, 2010, 2013, 2016
######################################################################
function perform_outlook_checks()
{
  local_var vuln, checks, path;
  vuln = 0;
  checks = make_array(
    "14.0", make_array("version", "14.0.7210.5000", "kb", "4022205"), # 2010
    "15.0", make_array("version", "15.0.5041.1000", "kb", "4022169"), # 2013
    "16.0", make_nested_list(
      make_array("version", "16.0.4705.1000", "channel", "MSI", "kb", kb16), # 2016
      make_array("version", "16.0.9330.2118", "channel", "Current", "kb", kb16), # Monthly
      make_array("version", "16.0.9126.2227", "channel", "First Release for Deferred", "kb", kb16), # Targeted
      make_array("version", "16.0.8431.2270", "channel", "Deferred", "channel_version", "1708", "kb", kb16), # Semi-Annual
      make_array("version", "16.0.8201.2278", "channel", "Deferred", "kb", kb16) # Deferred
    )
  );
  if (hotfix_check_office_product(product:"Outlook", checks:checks, bulletin:bulletin))
    vuln += 1;

  return vuln;
}


######################################################################
# MAIN
######################################################################
vuln = perform_outlook_checks();

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

