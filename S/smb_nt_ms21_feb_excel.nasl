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
  script_id(146336);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id(
    "CVE-2021-24067",
    "CVE-2021-24068",
    "CVE-2021-24069",
    "CVE-2021-24070"
  );
  script_xref(name:"MSKB", value:"4493222");
  script_xref(name:"MSKB", value:"4493211");
  script_xref(name:"MSKB", value:"4493196");
  script_xref(name:"MSFT", value:"MS21-4493222");
  script_xref(name:"MSFT", value:"MS21-4493211");
  script_xref(name:"MSFT", value:"MS21-4493196");
  script_xref(name:"IAVA", value:"2021-A-0067-S");

  script_name(english:"Security Updates for Microsoft Excel Products (February 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Excel Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Excel Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-24067,
    CVE-2021-24068, CVE-2021-24069, CVE-2021-24070)");
  # https://support.microsoft.com/en-us/office/description-of-the-security-update-for-excel-2010-february-9-2021-kb4493222-67c59c71-57c2-6441-5132-a58cbbf59903
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1bb1a89a");
  # https://support.microsoft.com/en-us/office/description-of-the-security-update-for-excel-2013-february-9-2021-kb4493211-d7481d05-31c1-4568-1a09-f2bc4721bf38
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15b56b9e");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-excel-2016-february-9-2021-kb4493196-3002e63d-ab12-1d79-772d-255b36774b6a
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43db639c");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4493222
  -KB4493211
  -KB4493196

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-24070");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_office_compatibility_pack_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS21-02';
kbs = make_list(
  '4493222',
  '4493196',
  '4493211'
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

port = kb_smb_transport();

checks = make_array(
  '14.0', make_array('sp', 2, 'version', '14.0.7265.5000', 'kb', '4493222'),
  '15.0', make_array('sp', 1, 'version', '15.0.5319.1000', 'kb', '4493211'),
  '16.0', make_nested_list(make_array('sp', 0, 'version', '16.0.5122.1000', 'channel', 'MSI', 'kb', '4493196')
  )
);

if (hotfix_check_office_product(product:'Excel', checks:checks, bulletin:bulletin))
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
