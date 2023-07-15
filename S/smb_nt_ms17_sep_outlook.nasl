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
  script_id(103456);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-0106",
    "CVE-2017-0204",
    "CVE-2017-8506",
    "CVE-2017-8507",
    "CVE-2017-8508",
    "CVE-2017-8571",
    "CVE-2017-8572",
    "CVE-2017-8663"
  );
  script_bugtraq_id(
    97413,
    97458,
    98811,
    98827,
    98828,
    99452,
    99453,
    100004
  );
  script_xref(name:"MSKB", value:"4011089");
  script_xref(name:"MSFT", value:"MS17-4011089");
  script_xref(name:"MSKB", value:"4011110");
  script_xref(name:"MSFT", value:"MS17-4011110");
  script_xref(name:"MSKB", value:"4011091");
  script_xref(name:"MSFT", value:"MS17-4011091");
  script_xref(name:"MSKB", value:"4011090");
  script_xref(name:"MSFT", value:"MS17-4011090");

  script_name(english:"Security Updates for Outlook (September 2017)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Outlook installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Outlook installed on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - A remote code execution vulnerability exists in the
    way that Microsoft Outlook parses specially crafted
    email messages. An attacker who successfully exploited
    the vulnerability could take control of an affected
    system to then install programs; view, change, or
    delete data; or create new accounts with full user
    rights. (CVE-2017-0106)

  - A security feature bypass vulnerability exists in
    Microsoft Office software when it improperly handles the
    parsing of file formats. To exploit the vulnerability,
    an attacker would have to convince a user to open a
    specially crafted file. (CVE-2017-0204)

  - A remote code execution vulnerability exists when
    Microsoft Office improperly validates input before
    loading dynamic link library (DLL) files. An attacker
    who successfully exploited this vulnerability could take
    control of an affected system to then install programs;
    view, change, or delete data; or create new accounts
    with full user rights. (CVE-2017-8506)

  - A remote code execution vulnerability exists in the way
    that Microsoft Outlook parses specially crafted email
    messages. An attacker who successfully exploited this
    vulnerability could take control of an affected system.
   (CVE-2017-8507)

  - A security feature bypass vulnerability exists in
    Microsoft Office software when it improperly handles the
    parsing of file formats. (CVE-2017-8508)

  - A security feature bypass vulnerability exists when
    Microsoft Office Outlook improperly handles input.
    An attacker who successfully exploited the vulnerability
    could execute arbitrary commands. (CVE-2017-8571)

  - An information disclosure vulnerability exists when
    Microsoft Outlook fails to properly validate
    authentication requests. (CVE-2017-8572)

  - A remote code execution vulnerability exists in the way
    that Microsoft Outlook parses specially crafted email
    messages. An attacker who successfully exploited the 
    vulnerability could take control of an affected system.
    (CVE-2017-8663)");
  # https://support.microsoft.com/en-us/help/4011089/descriptionofthesecurityupdateforoutlook2010september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ac9b313");
  # https://support.microsoft.com/en-us/help/4011086/descriptionofthesecurityupdateforoutlook2007september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f4ab525");
  # https://support.microsoft.com/en-nz/help/4011110/descriptionofthesecurityupdateforoutlook2007september19-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16a66c3d");
  # https://support.microsoft.com/en-us/help/4011091/descriptionofthesecurityupdateforoutlook2016september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5d09682");
  # https://support.microsoft.com/en-us/help/4011090/descriptionofthesecurityupdateforoutlook2013september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92c027cb");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Outlook 2007, 2010, 2013,
and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8663");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
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
  '4011110', # 2007 / 12.0
  '4011089', # 2010 / 14.0
  '4011090', # 2013 / 15.0
  '4011091'  # 2016 / 16.0
);
kb16 = '4011091';

if (get_kb_item("Host/patch_management_checks")) 
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

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
    "12.0", make_array("version", "12.0.6776.5000", "kb", "4011110"), # 2007
    "14.0", make_array("version", "14.0.7187.5000", "kb", "4011089"), # 2010
    "15.0", make_array("version", "15.0.4963.1000", "kb", "4011090"), # 2013
    "16.0", make_nested_list(
      make_array("version", "16.0.4588.1000", "channel", "MSI", "kb", kb16),
      make_array("version", "16.0.8326.2107", "channel", "Current", "kb", kb16),
      make_array("version", "16.0.8201.2193", "channel", "Deferred", "channel_version", "1705", "kb", kb16),
      make_array("version", "16.0.7766.2116", "channel", "Deferred", "kb", kb16),
      make_array("version", "16.0.8431.2079", "channel", "First Release for Deferred", "kb", kb16)
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

