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
  script_id(110989);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/24");

  script_cve_id("CVE-2018-8312");
  script_bugtraq_id(104645);
  script_xref(name:"MSKB", value:"4018351");
  script_xref(name:"MSKB", value:"4018338");
  script_xref(name:"MSFT", value:"MS18-4018351");
  script_xref(name:"MSFT", value:"MS18-4018338");
  script_xref(name:"IAVA", value:"2018-A-0217-S");

  script_name(english:"Security Updates for Microsoft Access Products (July 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Access Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Access Products are missing a security update.
It is, therefore, affected by the following vulnerability :

  - A remote code execution vulnerability exists when
    Microsoft Access fails to properly handle objects in
    memory. An attacker who successfully exploited the
    vulnerability could take control of the affected system.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights. Users whose accounts are configured to have
    fewer user rights on the system could be less impacted
    than users who operate with administrative user rights.
    (CVE-2018-8312)");
  # https://support.microsoft.com/en-us/help/4018351/description-of-the-security-update-for-access-2013-july-10-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af2dfe79");
  # https://support.microsoft.com/en-us/help/4018338/description-of-the-security-update-for-access-2016-july-10-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86c24ad7");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4018351
  -KB4018338");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8312");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:access");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_access_installed.nbin");
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
  '4018351', # Access 2013 SP1
  '4018338'  # Access 2016
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Access 2013, 2016
######################################################################
kb16 = "4018338";
access_checks = make_array(
  "15.0", make_array("sp", 1, "version", "15.0.5045.1000", "kb", "4018351"),
  "16.0", make_nested_list(
    make_array("sp", 0, "version", "16.0.4711.1000", "channel", "MSI", "kb", kb16),
    make_array("sp", 0, "version", "16.0.9126.2259", "channel", "Deferred", "channel_version", "1803", "kb", kb16),
    make_array("sp", 0, "version", "16.0.8431.2280", "channel", "Deferred", "kb", kb16),
    make_array("sp", 0, "version", "16.0.9126.2259", "channel", "First Release for Deferred", "kb", kb16),
    make_array("sp", 0, "version", "16.0.10228.20104", "channel", "Current", "kb", kb16)
  )
);
if (hotfix_check_office_product(product:"Access", checks:access_checks, bulletin:bulletin))
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
