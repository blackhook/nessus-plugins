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
  script_id(103138);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-8631", "CVE-2017-8632");
  script_bugtraq_id(100734, 100751);
  script_xref(name:"MSKB", value:"4011108");
  script_xref(name:"MSKB", value:"4011062");
  script_xref(name:"MSKB", value:"4011061");
  script_xref(name:"MSFT", value:"MS17-4011050");
  script_xref(name:"MSFT", value:"MS17-4011108");
  script_xref(name:"MSFT", value:"MS17-4011062");
  script_xref(name:"MSFT", value:"MS17-4011061");
  script_xref(name:"IAVA", value:"2017-A-0274");

  script_name(english:"Security Update for Microsoft Office Excel Products (September 2017)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Excel Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Excel Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Office software when it fails to properly
    handle objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user. Exploitation of
    this vulnerability requires that a user open a specially
    crafted file with an affected version of Microsoft
    Office software. In an email attack scenario, an
    attacker could exploit the vulnerability by sending the
    specially crafted file to the user and convincing the
    user to open the file. In a web-based attack scenario,
    an attacker could host a website (or leverage a
    compromised website that accepts or hosts user-provided
    content) that contains a specially crafted file that is
    designed to exploit the vulnerability. However, an
    attacker would have no way to force the user to visit
    the website. Instead, an attacker would have to convince
    the user to click a link, typically by way of an
    enticement in an email or Instant Messenger message, and
    then convince the user to open the specially crafted
    file. The security update addresses the vulnerability by
    correcting how Microsoft Office handles files in memory.
    (CVE-2017-8631, CVE-2017-8632)");
  # https://support.microsoft.com/en-us/help/4011108/descriptionofthesecurityupdateforexcel2013september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d426bc7");
  # https://support.microsoft.com/en-us/help/4011050/descriptionofthesecurityupdateforexcel2016september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2583452");
  # https://support.microsoft.com/en-us/help/4011061/descriptionofthesecurityupdateforexcel2010september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8028c458");
  # https://support.microsoft.com/en-us/help/4011062/descriptionofthesecurityupdateforexcel2007september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7194ec3f");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4011108
  -KB4011050
  -KB4011061
  -KB4011062");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8632");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS17-09";
kbs = make_list(
  '4011062', # Excel 2007 SP3
  '4011061', # Excel 2010 SP2
  '4011050', # Excel 2016
  '4011108' # Excel 2013 SP1
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();


######################################################################
# Excel 2007, 2010, 2013, 2016
######################################################################

kb16 = "4011050";
excel_checks = make_array(
  "12.0", make_array("sp", 3, "version", "12.0.6776.5000", "kb", "4011062"),
  "14.0", make_array("sp", 2, "version", "14.0.7188.5000", "kb", "4011061"),
  "15.0", make_array("sp", 1, "version", "15.0.4963.1000", "kb", "4011108"),
  "16.0", make_nested_list(
    make_array("sp", 0, "version", "16.0.4588.1000", "channel", "MSI", "kb", kb16),
    make_array("sp", 0, "version", "16.0.7766.2116", "channel", "Deferred", "kb", kb16),
    make_array("sp", 0, "version", "16.0.8201.2193", "channel", "Deferred", "channel_version", "1705", "kb", kb16),
    make_array("sp", 0, "version", "16.0.8431.2079", "channel", "First Release for Deferred", "kb", kb16),
    make_array("sp", 0, "version", "16.0.8326.2107", "channel", "Current", "kb", kb16)
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
