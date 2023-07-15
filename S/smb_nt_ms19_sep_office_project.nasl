#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.


include("compat.inc");

if (description)
{
  script_id(128686);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id("CVE-2019-1264");
  script_xref(name:"MSKB", value:"4464548");
  script_xref(name:"MSKB", value:"4475589");
  script_xref(name:"MSKB", value:"4461631");
  script_xref(name:"MSFT", value:"MS19-4464548");
  script_xref(name:"MSFT", value:"MS19-4475589");
  script_xref(name:"MSFT", value:"MS19-4461631");

  script_name(english:"Security Updates for Microsoft Project (September 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Project installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Project installation on the remote host
is missing a security update. It is, therefore, affected by
the following vulnerability :

  - A security feature bypass vulnerability exists when
    Microsoft Office improperly handles input. An attacker
    who successfully exploited the vulnerability could
    execute arbitrary commands. In a file-sharing attack
    scenario, an attacker could provide a specially crafted
    document file designed to exploit the vulnerability, and
    then convince a user to open the document file and
    interact with the document by clicking a specific cell.
    The update addresses the vulnerability by correcting how
    Microsoft Office handles input. (CVE-2019-1264)");
  # https://support.microsoft.com/en-us/help/4464548/security-update-for-project-2013-september-10-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?438eb6e8");
  # https://support.microsoft.com/en-us/help/4475589/security-update-for-project-2016-september-10-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?65dc9fca");
  # https://support.microsoft.com/en-us/help/4461631/security-update-for-project-2010-september-10-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f44ae26");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4464548
  -KB4475589
  -KB4461631");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1264");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
include('install_func.inc');

global_var vuln;

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS19-09';
kbs = make_list(
  '4461631', # 2010
  '4464548', # 2013
  '4475589'  # 2016
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

port = kb_smb_transport();

######################################################################
# project 2010, 2013, 2016
######################################################################
project_checks = make_array(
  "14.0", make_array('sp', 2, 'version', "14.0.7237.5000", 'kb', '4461631'),
  "15.0", make_array('sp', 1, 'version', "15.0.5172.1000", 'kb', '4464548'),
  "16.0", make_nested_list(make_array('version', "16.0.4900.1000", 'channel', 'MSI', 'kb', '4475589'))
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
