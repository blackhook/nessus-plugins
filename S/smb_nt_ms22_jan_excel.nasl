#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc. 
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156628);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id("CVE-2022-21840", "CVE-2022-21841");
  script_xref(name:"MSKB", value:"5002128");
  script_xref(name:"MSKB", value:"5002114");
  script_xref(name:"MSFT", value:"MS22-5002128");
  script_xref(name:"MSFT", value:"MS22-5002114");
  script_xref(name:"IAVA", value:"2022-A-0008-S");

  script_name(english:"Security Updates for Microsoft Excel Products (January 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Excel Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Excel Products are missing a security update. It is, therefore, affected by the following
vulnerabilities:

  - Two remote code execution vulnerabilities. An attacker can exploit these to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2022-21840, CVE-2022-21841)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002128");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002114");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5002128
  -KB5002114

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21841");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-21840");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_office_compatibility_pack_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

var bulletin = 'MS22-01';
var kbs = make_list(
  '5002114',
  '5002128'
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

var port = kb_smb_transport();

var checks = make_array(
  '15.0', make_array('sp', 1, 'version', '15.0.5415.1000', 'kb', '5002128'),
  '16.0', make_nested_list(
    make_array('sp', 0, 'version', '16.0.5266.1000', 'channel', 'MSI', 'kb', '5002114')
  )
);

if (hotfix_check_office_product(product:'Excel', checks:checks, bulletin:bulletin))
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
