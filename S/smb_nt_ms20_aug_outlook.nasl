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
  script_id(139505);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/05");

  script_cve_id("CVE-2020-1483", "CVE-2020-1493");
  script_xref(name:"MSKB", value:"4484486");
  script_xref(name:"MSKB", value:"4484497");
  script_xref(name:"MSKB", value:"4484475");
  script_xref(name:"MSFT", value:"MS20-4484486");
  script_xref(name:"MSFT", value:"MS20-4484497");
  script_xref(name:"MSFT", value:"MS20-4484475");
  script_xref(name:"IAVA", value:"2020-A-0360-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0101");

  script_name(english:"Security Updates for Outlook (August 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Outlook application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Outlook application installed on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Outlook when the software fails to properly
    handle objects in memory. An attacker who successfully
    exploited the vulnerability could run arbitrary code in
    the context of the current user. If the current user is
    logged on with administrative user rights, an attacker
    could take control of the affected system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2020-1483)

  - An information disclosure vulnerability exists when
    attaching files to Outlook messages. This vulnerability
    could potentially allow users to share attached files
    such that they are accessible by anonymous users where
    they should be restricted to specific users.
    (CVE-2020-1493)");
  # https://support.microsoft.com/en-us/help/4484486/security-update-for-outlook-2013-august-11-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb58ddc1");
  # https://support.microsoft.com/en-us/help/4484497/security-update-for-outlook-2010-august-11-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1dd03f9");
  # https://support.microsoft.com/en-us/help/4484475/security-update-for-outlook-2016-august-11-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2cefe80");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4484486
  -KB4484497
  -KB4484475

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1483");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

global_var vuln;

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS20-08';
kbs = make_list(
  '4484486',
  '4484475',
  '4484497'
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

port = kb_smb_transport();

checks = make_array(
  '14.0', make_array('sp', 2, 'version', '14.0.7256.5000', 'kb', '4484497'),
  '15.0', make_array('sp', 1, 'version', '15.0.5267.1000', 'kb', '4484486'),
  '16.0', make_nested_list(
    make_array('sp', 0, 'version', '16.0.5044.1000', 'channel', 'MSI', 'kb', '4484475'),
    #C2R
    make_array('version', '16.0.11328.20644', 'channel', 'Deferred'),
    make_array('version', '16.0.11929.20934', 'channel', 'Deferred', 'channel_version', '1908'),
    make_array('version', '16.0.13001.20520', 'channel', 'Enterprise Deferred', 'channel_version', '2006'),
    make_array('version', '16.0.12827.20656', 'channel', 'Enterprise Deferred'),
    make_array('version', '16.0.12527.20988', 'channel', 'First Release for Deferred'),
    make_array('version', '16.0.13029.20344', 'channel', 'Current'),
    # 2019 & Windows 7 365 temp fix 
    make_array('version', '16.0.12527.20988', 'channel', '2019 Retail'),
    make_array('version', '16.0.12527.20988', 'channel', '2019 Retail', 'channel_version', '2002'),
    make_array('version', '16.0.13029.20344', 'channel', '2019 Retail', 'channel_version', '2004'),
    make_array('version', '16.0.10364.20059', 'channel', '2019 Volume')
  )
);

if (hotfix_check_office_product(product:'Outlook', checks:checks, bulletin:bulletin))
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

