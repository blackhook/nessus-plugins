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
  script_id(131940);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id("CVE-2019-1461");
  script_xref(name:"MSKB", value:"4475601");
  script_xref(name:"MSKB", value:"4484094");
  script_xref(name:"MSKB", value:"4484169");
  script_xref(name:"MSFT", value:"MS19-4475601");
  script_xref(name:"MSFT", value:"MS19-4484094");
  script_xref(name:"MSFT", value:"MS19-4484169");

  script_name(english:"Security Updates for Microsoft Word Products (December 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Word Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Word Products are missing a security update.
It is, therefore, affected by the following vulnerability :

  - A denial of service vulnerability exists in Microsoft
    Word software when the software fails to properly handle
    objects in memory. An attacker who successfully
    exploited the vulnerability could cause a remote denial
    of service against a system. Exploitation of the
    vulnerability requires that a specially crafted document
    be sent to a vulnerable user. The security update
    addresses the vulnerability by correcting how Microsoft
    Word handles objects in memory. (CVE-2019-1461)");
  # https://support.microsoft.com/en-us/help/4475601/security-update-for-word-2010-december-10-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?61994611");
  # https://support.microsoft.com/en-us/help/4484094/security-update-for-word-2013-december-10-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8eef1e05");
  # https://support.microsoft.com/en-us/help/4484169/security-update-for-word-2016-december-10-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5004b05");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4475601
  -KB4484094
  -KB4484169
For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1461");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS19-12';

kbs = make_list(
  '4475601', # Word 2010
  '4484094', # Word 2013
  '4484169'  # Word 2016
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

port = kb_smb_transport();

checks = make_array(
  '14.0', make_array('sp', 2, 'version', '14.0.7243.5000', 'kb', '4475601'),
  '15.0', make_array('sp', 1, 'version', '15.0.5197.1000', 'kb', '4484094'),
  '16.0', make_nested_list(make_array('sp', 0, 'version', '16.0.4939.1000', 'channel', 'MSI', 'kb', '4484169'))
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
