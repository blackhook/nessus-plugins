##
# (C) Tenable Network Security, Inc.
##
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(141415);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-16933");
  script_xref(name:"MSKB", value:"4486703");
  script_xref(name:"MSKB", value:"4486692");
  script_xref(name:"MSKB", value:"4486679");
  script_xref(name:"MSFT", value:"MS20-4486703");
  script_xref(name:"MSFT", value:"MS20-4486692");
  script_xref(name:"MSFT", value:"MS20-4486679");
  script_xref(name:"CEA-ID", value:"CEA-2020-0126");

  script_name(english:"Security Updates for Microsoft Word Products (October 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Word Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Word Products are missing a security update.
It is, therefore, affected by the following vulnerability :

  - A security feature bypass vulnerability exists in
    Microsoft Word software when it fails to properly handle
    .LNK files. An attacker who successfully exploited the
    vulnerability could use a specially crafted file to
    perform actions in the security context of the current
    user. For example, the file could then take actions on
    behalf of the logged-on user with the same permissions
    as the current user.  (CVE-2020-16933)");
  # https://support.microsoft.com/en-us/help/4486703/security-update-for-word-2010-october-13-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c796608f");
  # https://support.microsoft.com/en-us/help/4486692/security-update-for-word-2013-october-13-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4409704");
  # https://support.microsoft.com/en-us/help/4486679/security-update-for-word-2016-october-13-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8069ae47");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4486703
  -KB4486692
  -KB4486701
  -KB4486679

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16933");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/13");

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

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS20-10';
kbs = make_list(
  '4486703',
  '4486692',
  '4486679'
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

port = kb_smb_transport();

checks = make_array(
  '14.0', make_array('sp', 2, 'version', '14.0.7261.5000', 'kb', '4486703'),
  '15.0', make_array('sp', 1, 'version', '15.0.5285.1000', 'kb', '4486692'),
  '16.0', make_nested_list(make_array('sp', 0, 'version', '16.0.5071.1000', 'channel', 'MSI', 'kb', '4486679')
    # 2019 & Windows 7 365 temp fix 
  )
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
