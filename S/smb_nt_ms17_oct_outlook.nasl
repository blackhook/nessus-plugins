#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(103752);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/17");

  script_cve_id("CVE-2017-11774", "CVE-2017-11776");
  script_bugtraq_id(101098, 101106);
  script_xref(name:"MSFT", value:"MS17-4011162");
  script_xref(name:"MSFT", value:"MS17-4011178");
  script_xref(name:"MSFT", value:"MS17-4011196");
  script_xref(name:"MSKB", value:"4011178");
  script_xref(name:"MSKB", value:"4011196");
  script_xref(name:"IAVA", value:"2017-A-0291-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Security Updates for Outlook (October 2017)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Outlook installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Outlook installed on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - An information disclosure vulnerability exists when
    Microsoft Outlook fails to establish a secure
    connection. An attacker who exploited the vulnerability
    could use it to obtain the email content of a user. The
    security update addresses the vulnerability by
    preventing Outlook from disclosing user email content.
    (CVE-2017-11776)

  - A security feature bypass vulnerability exists when
    Microsoft Office improperly handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could execute arbitrary commands. In a file-sharing
    attack scenario, an attacker could provide a specially
    crafted document file designed to exploit the
    vulnerability, and then convince users to open the
    document file and interact with the document. The
    security update addresses the vulnerability by
    correcting how Microsoft Office handles objects in
    memory. (CVE-2017-11774)");
  # https://support.microsoft.com/en-us/help/4011162/description-of-the-security-update-for-outlook-2016-october-10-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67eda8b2");
  # https://support.microsoft.com/en-us/help/4011178/descriptionofthesecurityupdateforoutlook2013october10-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6c94157");
  # https://support.microsoft.com/en-us/help/4011196/descriptionofthesecurityupdateforoutlook2010october10-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fcfcd1f7");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Outlook 2010, 2013,
and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11774");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS17-10";
kbs = make_list(
  '4011196', # 2010 / 14.0
  '4011178', # 2013 / 15.0
  '4011162'  # 2016 / 16.0
);
kb16 = '4011162';

if (get_kb_item("Host/patch_management_checks")) 
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

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
    "14.0", make_array("version", "14.0.7189.5000", "kb", "4011196"), # 2010
    "15.0", make_array("version", "15.0.4971.1000", "kb", "4011178"), # 2013
    "16.0", make_nested_list(
      make_array("version", "16.0.4600.1000", "channel", "MSI", "kb", kb16),
      make_array("version", "16.0.8431.2107", "channel", "Current", "kb", kb16),
      make_array("version", "16.0.8201.2200", "channel", "Deferred", "channel_version", "1705", "kb", kb16),
      make_array("version", "16.0.7766.2119", "channel", "Deferred", "kb", kb16),
      make_array("version", "16.0.8431.2107", "channel", "First Release for Deferred", "kb", kb16)
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

