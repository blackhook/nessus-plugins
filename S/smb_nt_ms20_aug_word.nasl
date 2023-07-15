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
  script_id(139507);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-1502", "CVE-2020-1503", "CVE-2020-1583");
  script_xref(name:"MSKB", value:"4484494");
  script_xref(name:"MSKB", value:"4484484");
  script_xref(name:"MSKB", value:"4484474");
  script_xref(name:"MSFT", value:"MS20-4484494");
  script_xref(name:"MSFT", value:"MS20-4484484");
  script_xref(name:"MSFT", value:"MS20-4484474");
  script_xref(name:"IAVA", value:"2020-A-0359-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0101");

  script_name(english:"Security Updates for Microsoft Word Products (August 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Word Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Word Products are missing security updates. It
is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists when
    Microsoft Word improperly discloses the contents of its
    memory. An attacker who exploited the vulnerability
    could use the information to compromise the user’s
    computer or data.  (CVE-2020-1502)

  - An information disclosure vulnerability exists when
    Microsoft Word improperly discloses the contents of its
    memory. An attacker who exploited the vulnerability
    could use the information to compromise the users
    computer or data.  (CVE-2020-1503, CVE-2020-1583)");
  # https://support.microsoft.com/en-us/help/4484494/security-update-for-word-2010-august-11-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e7fda134");
  # https://support.microsoft.com/en-us/help/4484484/security-update-for-word-2013-august-11-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a78c2b19");
  # https://support.microsoft.com/en-us/help/4484474/security-update-for-word-2016-august-11-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de5102e9");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4484494
  -KB4484484
  -KB4484474

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1583");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS20-08';
kbs = make_list(
  '4484494',
  '4484474',
  '4484484'
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

port = kb_smb_transport();

checks = make_array(
  '14.0', make_array('sp', 2, 'version', '14.0.7256.5000', 'kb', '4484461'),
  '15.0', make_array('sp', 1, 'version', '15.0.5267.1000', 'kb', '4484449'),
  '16.0', make_nested_list(
    make_array('sp', 0, 'version', '16.0.5044.1000', 'channel', 'MSI', 'kb', '4484465'))
);

if (hotfix_check_office_product(product:'Word', checks:checks, bulletin:bulletin))
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


