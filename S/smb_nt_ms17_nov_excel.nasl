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
  script_id(104556);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2017-11877", "CVE-2017-11878", "CVE-2017-11884");
  script_bugtraq_id(100734, 100751, 101766);
  script_xref(name:"MSKB", value:"4011197");
  script_xref(name:"MSKB", value:"4011220");
  script_xref(name:"MSKB", value:"4011233");
  script_xref(name:"MSKB", value:"4011199");
  script_xref(name:"MSFT", value:"MS17-4011197");
  script_xref(name:"MSFT", value:"MS17-4011220");
  script_xref(name:"MSFT", value:"MS17-4011233");
  script_xref(name:"MSFT", value:"MS17-4011199");
  script_xref(name:"IAVA", value:"2017-A-0337-S");

  script_name(english:"Security Updates for Microsoft Excel Products (November 2017)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Excel Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Excel Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Office software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2017-11878)

  - A security feature bypass vulnerability exists in
    Microsoft Office software by not enforcing macro
    settings on an Excel document. The security feature
    bypass by itself does not allow arbitrary code
    execution. To successfully exploit the vulnerability, an
    attacker would have to embed a control in an Excel
    worksheet that specifies a macro should be run.
    (CVE-2017-11877)

  - A remote code execution vulnerability exists in
    Microsoft Office software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with
    full user rights. Users whose accounts are configured
    to have fewer user rights on the system could be less
    impacted than users who operate with administrative
    user rights.

    Exploitation of the vulnerability requires that a user
    open a specially crafted file with an affected version
    of Microsoft Office. In an email attack scenario, an
    attacker could exploit the vulnerability by sending the
    specially crafted file to the user and convincing the
    user to open the file. In a web-based attack scenario,
    an attacker could host a website (or leverage a
    compromised website that accepts or hosts user-provided
    content) containing a specially crafted file designed
    to exploit the vulnerability. An attacker would have no
    way to force users to visit the website. Instead, an
    attacker would have to convince users to click a link,
    typically by way of an enticement in an email or
    instant message, and then convince them to open the
    specially crafted file.  (CVE-2017-11884)");
  # https://support.microsoft.com/en-us/help/4011197/descriptionofthesecurityupdateforexcel2010november14-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92b81e09");
  # https://support.microsoft.com/en-us/help/4011220/description-of-the-security-update-for-excel-2016-november-14-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec4b4942");
  # https://support.microsoft.com/en-us/help/4011233/description-of-the-security-update-for-excel-2013-november-14-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79b55073");
  # https://support.microsoft.com/en-us/help/4011199/descriptionofthesecurityupdateforexcel2007november14-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c66f32ec");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB4011197
  -KB4011220
  -KB4011233
  -KB4011199");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11884");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
include("misc_func.inc");
include("install_func.inc");

global_var vuln;

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS17-11";
kbs = make_list(
  '4011197', # Excel 2010 SP2
  '4011199', # Excel 2007 SP3
  '4011220', # Excel 2016
  '4011233'  # Excel 2013 SP1
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();


######################################################################
# Excel 2007, 2010, 2013, 2016
######################################################################

kb16 = "4011220";
excel_checks = make_array(
  "12.0", make_array("sp", 3, "version", "12.0.6780.5000", "kb", "4011199"),
  "14.0", make_array("sp", 2, "version", "14.0.7190.5000", "kb", "4011197"),
  "15.0", make_array("sp", 1, "version", "15.0.4981.1000", "kb", "4011233"),
  "16.0", make_nested_list(
    make_array("sp", 0, "version", "16.0.4615.1000", "channel", "MSI", "kb", kb16),
    make_array("sp", 0, "version", "16.0.7766.2122", "channel", "Deferred", "kb", kb16),
    make_array("sp", 0, "version", "16.0.8201.2207", "channel", "Deferred", "channel_version", "1705", "kb", kb16),
    make_array("sp", 0, "version", "16.0.8431.2110", "channel", "First Release for Deferred", "kb", kb16),
    make_array("sp", 0, "version", "16.0.8625.2127", "channel", "Current", "kb", kb16)
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
