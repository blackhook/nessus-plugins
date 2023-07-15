#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.

include('compat.inc');

if (description)
{
  script_id(137268);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2020-1322");
  script_xref(name:"MSKB", value:"4484369");
  script_xref(name:"MSKB", value:"4484399");
  script_xref(name:"MSKB", value:"4484387");
  script_xref(name:"MSFT", value:"MS20-4484369");
  script_xref(name:"MSFT", value:"MS20-4484399");
  script_xref(name:"MSFT", value:"MS20-4484387");
  script_xref(name:"IAVA", value:"2020-A-0245-S");

  script_name(english:"Microsoft Information Disclosure Vulnerability (June 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Project installation on the remote host is missing the June 2020 security Update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Project installation on the remote host is missing a security update. Therefore, 
An information disclosure vulnerability exists in Microsoft Project due to an uninitialized variable. 
An attacker could read out of bounds memory to disclose potentially sensitive information.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4484369");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4484387");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4484399");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4484369
  -KB4484399
  -KB4484387");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1322");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "office_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');
bulletin = 'MS20-04';

kbs = make_list(
  '4484387', # 2010
  '4484369', # 2013
  '4484399'  # 2016
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

port = kb_smb_transport();

project_checks = make_array(
  "14.0", make_array('sp', 2, 'version', "14.0.7252.5000", 'kb', '4484387'),
  "15.0", make_array('sp', 1, 'version', "15.0.5249.1000", 'kb', '4484369'),
  "16.0", make_nested_list(
    make_array('version', "16.0.5017.1000", 'channel', 'MSI', 'kb', '4484399')
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
