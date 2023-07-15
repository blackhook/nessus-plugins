#
# (C) Tenable Network Security, Inc.
#



# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.



include('compat.inc');

if (description)
{
  script_id(135477);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/21");

  script_cve_id("CVE-2020-0760");
  script_xref(name:"MSKB", value:"4484125");
  script_xref(name:"MSKB", value:"4484269");
  script_xref(name:"MSKB", value:"4484132");
  script_xref(name:"MSFT", value:"MS20-4484125");
  script_xref(name:"MSFT", value:"MS20-4484269");
  script_xref(name:"MSFT", value:"MS20-4484132");
  script_xref(name:"IAVA", value:"2020-A-0146");

  script_name(english:"Microsoft Project RCE Vulnerability (April 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Project installation on the remote host is missing the April 2020 security Update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Project installation on the remote host is missing a security update. Therefore, 
a remote code execution vulnerability exists when Microsoft Office improperly loads arbitrary type libraries. 
An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights. 
Users whose accounts are configured to have fewer user rights on the system could be less impacted than users who 
operate with administrative user rights.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4484125");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4484132");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4484269");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4484125
  -KB4484269
  -KB4484132");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0760");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "office_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');
bulletin = 'MS20-04';

kbs = make_list(
  '4484132', # 2010
  '4484125', # 2013
  '4484269'  # 2016
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

port = kb_smb_transport();

project_checks = make_array(
  "14.0", make_array('sp', 2, 'version', "14.0.7246.5000", 'kb', '4484132'),
  "15.0", make_array('sp', 1, 'version', "15.0.5223.1000", 'kb', '4484125'),
  "16.0", make_nested_list(
    make_array('version', "16.0.4993.1001", 'channel', 'MSI', 'kb', '4484269')
    )
  );

if (hotfix_check_office_product(product:'Project', checks:project_checks, bulletin:bulletin))
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
