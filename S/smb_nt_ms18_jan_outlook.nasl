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
  script_id(105699);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2018-0791");
  script_bugtraq_id(102383);
  script_xref(name:"MSKB", value:"4011213");
  script_xref(name:"MSFT", value:"MS18-4011213");
  script_xref(name:"MSKB", value:"4011273");
  script_xref(name:"MSFT", value:"MS18-4011273");
  script_xref(name:"MSKB", value:"4011637");
  script_xref(name:"MSFT", value:"MS18-4011637");
  script_xref(name:"MSKB", value:"4011626");
  script_xref(name:"MSFT", value:"MS18-4011626");
  script_xref(name:"IAVA", value:"2018-A-0009-S");

  script_name(english:"Security Updates for Outlook (January 2018)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Outlook installed on the remote host is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Outlook installed on the remote host
is missing a security update. It is, therefore, affected by
a remote code execution vulnerability in the way that Microsoft
Outlook parses specially crafted email messages. An attacker who
successfully exploited the vulnerability could take control of an
affected system, then install programs; view, change, or delete
data; or create new accounts with full user rights.");
  # https://support.microsoft.com/en-us/help/4011213/descriptionofthesecurityupdateforoutlook2007january9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b69062a0");
  # https://support.microsoft.com/en-us/help/4011273/descriptionofthesecurityupdateforoutlook2010january9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ac0f408");
  # https://support.microsoft.com/en-us/help/4011637/descriptionofthesecurityupdateforoutlook2013january9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3387b83");
  # https://support.microsoft.com/en-us/help/4011626/descriptionofthesecurityupdateforoutlook2016january9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ad5d59d");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Outlook 2007, 2010, 2013,
and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0791");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS18-01";
kbs = make_list(
  '4011213', # 2007 SP3 / 12.0
  '4011273', # 2010 SP2 / 14.0
  '4011637', # 2013 SP1 / 15.0
  '4011626'  # 2016     / 16.0
);
kb16 = '4011626';

if (get_kb_item("Host/patch_management_checks")) 
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

port = kb_smb_transport();

######################################################################
# Outlook 2010, 2013, 2016
######################################################################
function perform_outlook_checks()
{
  local_var vuln, checks, path;
  vuln = 0;
  checks = make_array(
    "12.0", make_array("version", "12.0.6784.5000", "kb", "4011213"), # 2007
    "14.0", make_array("version", "14.0.7192.5000", "kb", "4011273"), # 2010
    "15.0", make_array("version", "15.0.4997.1000", "kb", "4011637"), # 2013
    "16.0", make_nested_list(
      make_array("version", "16.0.4639.1000", "channel", "MSI", "kb", kb16), # 2016
      make_array("version", "16.0.8730.2175", "channel", "Current", "kb", kb16), # Monthly
      make_array("version", "16.0.8431.2153", "channel", "First Release for Deferred", "kb", kb16), # Targeted
      make_array("version", "16.0.8431.2153", "channel", "Deferred", "channel_version", "1708", "kb", kb16), # Semi-Annual
      make_array("version", "16.0.8201.2217", "channel", "Deferred", "kb", kb16) # Deferred
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
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

