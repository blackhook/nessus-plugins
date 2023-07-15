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
  script_id(108301);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id("CVE-2018-0919", "CVE-2018-0922");
  script_bugtraq_id(103311, 103314);
  script_xref(name:"MSKB", value:"4011721");
  script_xref(name:"MSKB", value:"4011674");
  script_xref(name:"MSKB", value:"4011730");
  script_xref(name:"MSKB", value:"4011695");
  script_xref(name:"MSFT", value:"MS18-4011721");
  script_xref(name:"MSFT", value:"MS18-4011674");
  script_xref(name:"MSFT", value:"MS18-4011730");
  script_xref(name:"MSFT", value:"MS18-4011695");
  script_xref(name:"IAVA", value:"2018-A-0077-S");

  script_name(english:"Security Updates for Microsoft Word Products (March 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Word Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Word Products are missing security updates. It
is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists when
    Microsoft Office software reads out of bound memory due
    to an uninitialized variable, which could disclose the
    contents of memory. An attacker who successfully
    exploited the vulnerability could view out of bound
    memory. Exploitation of the vulnerability requires that
    a user open a specially crafted file with an affected
    version of Microsoft Office software. The security
    update addresses the vulnerability by properly
    initializing the affected variable. (CVE-2018-0919)

  - A remote code execution vulnerability exists in
    Microsoft Office software when the Office software fails
    to properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-0922)");
  # https://support.microsoft.com/en-us/help/4011721/description-of-the-security-update-for-word-2007-march-13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a931ed8a");
  # https://support.microsoft.com/en-us/help/4011674/descriptionofthesecurityupdateforword2010march13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28553b79");
  # https://support.microsoft.com/en-us/help/4011730/descriptionofthesecurityupdateforword2016march13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37a5148f");
  # https://support.microsoft.com/en-us/help/4011695/descriptionofthesecurityupdateforword2013march13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?797b3826");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4011721
  -KB4011674
  -KB4011730
  -KB4011695");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0922");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS18-03";
kbs = make_list(
  '4011721', # Word 2007 SP3
  '4011674', # Word 2010 SP2
  '4011695', # Word 2013 SP1
  '4011730'  # Word 2016
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Word 2007, 2010, 2013, 2016
######################################################################
function perform_word_checks()
{
  local_var word_checks, kb16;

  kb16 = "4011730";
  word_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6786.5000", "kb", "4011721"),
    "14.0", make_array("sp", 2, "version", "14.0.7195.5000", "kb", "4011674"),
    "15.0", make_array("sp", 1, "version", "15.0.5015.1000", "kb", "4011695"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4666.1000", "channel", "MSI", "kb", kb16),
      make_array("sp", 0, "version", "16.0.8431.2236", "channel", "Deferred", "channel_version", "1708", "kb", kb16),
      make_array("sp", 0, "version", "16.0.8201.2265", "channel", "Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.9126.2072", "channel", "First Release for Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.9029.2253", "channel", "Current", "kb", kb16)

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
