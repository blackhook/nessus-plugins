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
  script_id(133622);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/17");

  script_cve_id("CVE-2020-0696");
  script_xref(name:"MSKB", value:"4484250");
  script_xref(name:"MSKB", value:"4484163");
  script_xref(name:"MSKB", value:"4484156");
  script_xref(name:"MSFT", value:"MS20-4484250");
  script_xref(name:"MSFT", value:"MS20-4484163");
  script_xref(name:"MSFT", value:"MS20-4484156");

  script_name(english:"Security Updates for Outlook (February 2020)");
  script_summary(english:"Checks for Microsoft February 2020 security update. (CVE-2020-0696)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Outlook application installed on the remote host is affected by a Security Feature Bypass Vulnerability (CVE-2020-0696).");
  script_set_attribute(attribute:"description", value:
"An security feature bypass exists in Outlook due to improper 
the parsing of URI formats. An unauthenticated, remote attacker 
can exploit this via a specially crafted URI. This can provide
opportunities for additional exploits.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4484250");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4484163");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4484156");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4484250
  -KB4484163
  -KB4484156");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0696");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS20-02';
kbs = make_list(
  '4484250',
  '4484163',
  '4484156'
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

port = kb_smb_transport();

checks = make_array(

  '14.0', make_array('sp', 2, 'version', '14.0.7245.5000', 'kb', '4484163'),
  '15.0', make_array('sp', 1, 'version', '15.0.5215.1000', 'kb', '4484156'),
  '16.0', make_nested_list(
    make_array('sp', 0, 'version', '16.0.4966.1000', 'channel', 'MSI', 'kb', '4484250'),
    # C2R
    make_array('version', '16.0.10730.20438', 'channel', 'Deferred'),
    make_array('version', '16.0.11328.20526', 'channel', 'Deferred', 'channel_version', '1902'),
    make_array('version', '16.0.11929.20606', 'channel', 'First Release for Deferred'),
    make_array('version', '16.0.12430.20264', 'channel', 'Current'),
    # 2019
    make_array('version', '16.0.12430.20264', 'channel', '2019 Retail'),
    make_array('version', '16.0.10356.20006', 'channel', '2019 Volume')

  )
);

if (hotfix_check_office_product(product:'Outlook', checks:checks, bulletin:bulletin))
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
