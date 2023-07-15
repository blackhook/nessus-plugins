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
  script_id(134382);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id("CVE-2020-0850", "CVE-2020-0892");
  script_xref(name:"MSKB", value:"4484268");
  script_xref(name:"MSKB", value:"4484240");
  script_xref(name:"MSKB", value:"4484231");
  script_xref(name:"MSFT", value:"MS20-4484268");
  script_xref(name:"MSFT", value:"MS20-4484240");
  script_xref(name:"MSFT", value:"MS20-4484231");

  script_name(english:"Security Updates for Microsoft Word Products (March 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Word Products are affected by a Remote Code Execution Vulnerability. (CVE-2020-0850, CVE-2020-0892)");
  script_set_attribute(attribute:"description", value:
"The Microsoft Word Products are missing security updates.
It is, therefore, affected by affected by the following vulnerability:

  - A remote code execution vulnerability exists in Microsoft Word software when it fails to properly handle objects in
    memory. An attacker who successfully exploited the vulnerability could use a specially crafted file to perform 
    actions in the security context of the current user. For example, the file could then take actions on behalf 
    of the logged-on user with the same permissions as the current user.

    To exploit the vulnerability, a user must open a specially crafted file with an affected version of Microsoft Word 
    software. In an email attack scenario, an attacker could exploit the vulnerability by sending the specially crafted
    file to the user and convincing the user to open the file. In a web-based attack scenario, an attacker could host a
    website (or leverage a compromised website that accepts or hosts user-provided content) that contains a specially 
    crafted file that is designed to exploit the vulnerability. However, an attacker would have no way to force the 
    user to visit the website. Instead, an attacker would have to convince the user to click a link, typically by way 
    of an enticement in an email or Instant Messenger message, and then convince the user to open the specially 
    crafted file. (CVE-2020-0850, CVE-2020-0892)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4484268");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4484240");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4484231");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4484268
  -KB4484240
  -KB4484231

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open Word and manually perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0892");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-0850");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('install_func.inc');

global_var vuln;

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS20-03';
kbs = make_list(
  '4484268',
  '4484240',
  '4484231'
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

port = kb_smb_transport();

checks = make_array(
  '14.0', make_array('sp', 2, 'version', '14.0.7246.5000', 'kb', '4484240'),
  '15.0', make_array('sp', 1, 'version', '15.0.5223.1000', 'kb', '4484231'),
  '16.0', make_nested_list(
    make_array('sp', 0, 'version', '16.0.4978.1000', 'channel', 'MSI', 'kb', '4484268'))
);

if (hotfix_check_office_product(product:'Word', checks:checks, bulletin:bulletin))
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
