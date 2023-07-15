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
  script_id(148464);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/11");

  script_cve_id("CVE-2021-28452");
  script_xref(name:"MSKB", value:"4504712");
  script_xref(name:"MSKB", value:"4504733");
  script_xref(name:"MSKB", value:"4493185");
  script_xref(name:"MSFT", value:"MS21-4504712");
  script_xref(name:"MSFT", value:"MS21-4504733");
  script_xref(name:"MSFT", value:"MS21-4493185");
  script_xref(name:"IAVA", value:"2021-A-0175-S");

  script_name(english:"Security Updates for Outlook (April 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Outlook application installed on the remote host is affected by a memory corruption vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Outlook application installed on the remote host is missing security updates. It is, therefore, affected
by a memory corruption vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4504712");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4504733");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4493185");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4504712
  -KB4504733
  -KB4493185

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic updates are enabled or open any office app and
manually perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28452");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

var bulletin = 'MS21-04';
var kbs = make_list(
  '4504712',
  '4504733',
  '4493185'
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

var port = kb_smb_transport();

var checks = make_array(
  '14.0', make_array('sp', 2, 'version', '14.0.7268.5000', 'kb', '4493185'),
  '15.0', make_array('sp', 1, 'version', '15.0.5337.1000', 'kb', '4504733'),
  '16.0', make_nested_list(
    make_array('sp', 0, 'version', '16.0.5149.1000', 'channel', 'MSI', 'kb', '4504712'),
    make_array('version', '16.0.13127.21506', 'channel', 'Deferred','channel_version', '2008'),
    make_array('version', '16.0.12527.21814', 'channel', 'Deferred'),
    make_array('version', '16.0.13801.20506', 'channel', 'Enterprise Deferred', 'channel_version', '2102'),
    make_array('version', '16.0.13628.20664', 'channel', 'Enterprise Deferred'),
    make_array('version', '16.0.13801.20506', 'channel', 'First Release for Deferred'),
    make_array('version', '16.0.13901.20400', 'channel', 'Current'),
    make_array('version', '16.0.10373.20050', 'channel', '2019 Volume'),
    make_array('version', '16.0.13901.20400', 'channel', '2019 Retail')
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
