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
  script_id(106807);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id("CVE-2018-0850", "CVE-2018-0852");
  script_bugtraq_id(102866, 102871);
  script_xref(name:"MSKB", value:"4011682");
  script_xref(name:"MSKB", value:"4011697");
  script_xref(name:"MSKB", value:"4011711");
  script_xref(name:"MSKB", value:"4011200");
  script_xref(name:"MSFT", value:"MS18-4011682");
  script_xref(name:"MSFT", value:"MS18-4011697");
  script_xref(name:"MSFT", value:"MS18-4011711");
  script_xref(name:"MSFT", value:"MS18-4011200");
  script_xref(name:"IAVA", value:"2018-A-0051-S");

  script_name(english:"Security Updates for Outlook (February 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Outlook application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Outlook application installed on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists when
    Microsoft Outlook initiates processing of incoming
    messages without sufficient validation of the formatting
    of the messages. An attacker who successfully exploited
    the vulnerability could attempt to force Outlook to load
    a local or remote message store (over SMB).
    (CVE-2018-0850)

  - A remote code execution vulnerability exists in
    Microsoft Outlook when the software fails to properly
    handle objects in memory. An attacker who successfully
    exploited the vulnerability could run arbitrary code in
    the context of the current user. If the current user is
    logged on with administrative user rights, an attacker
    could take control of the affected system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2018-0852)");
  # https://support.microsoft.com/en-us/help/4011682/descriptionofthesecurityupdateforoutlook2016february13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0d84fef");
  # https://support.microsoft.com/en-us/help/4011697/descriptionofthesecurityupdateforoutlook2013february13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4444a3b8");
  # https://support.microsoft.com/en-us/help/4011711/descriptionofthesecurityupdateforoutlook2010february13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13b4a7cf");
  # https://support.microsoft.com/en-us/help/4011200/descriptionofthesecurityupdateforoutlook2007february13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7de39c82");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this
issue:
  - KB4011682
  - KB4011697
  - KB4011711
  - KB4011200");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/13");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2020 Tenable Network Security, Inc.");

  script_dependencies(
    "office_installed.nasl",
    "smb_hotfixes.nasl",
    "ms_bulletin_checks_possible.nasl"
  );
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

bulletin = "MS18-02";
kbs = make_list(
  '4011200', # 2007 SP3 / 12.0
  '4011711', # 2010 SP2 / 14.0
  '4011697', # 2013 SP1 / 15.0
  '4011682'  # 2016     / 16.0
);
kb16 = '4011682';

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
    "12.0", make_array("version", "12.0.6785.5000", "kb", "4011200"), # 2007
    "14.0", make_array("version", "14.0.7194.5000", "kb", "4011711"), # 2010
    "15.0", make_array("version", "15.0.5007.1000", "kb", "4011697"), # 2013
    "16.0", make_nested_list(
      make_array("version", "16.0.4654.1000", "channel", "MSI", "kb", kb16), # 2016
      make_array("version", "16.0.9001.2171", "channel", "Current", "kb", kb16), # Monthly
      make_array("version", "16.0.8431.2215", "channel", "First Release for Deferred", "kb", kb16), # Targeted
      make_array("version", "16.0.8431.2215", "channel", "Deferred", "channel_version", "1708", "kb", kb16), # Semi-Annual
      make_array("version", "16.0.8201.2258", "channel", "Deferred", "kb", kb16) # Deferred
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

