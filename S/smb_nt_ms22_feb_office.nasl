#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc. 
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157433);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id(
    "CVE-2022-21988",
    "CVE-2022-22003",
    "CVE-2022-22004",
    "CVE-2022-23252"
  );
  script_xref(name:"MSKB", value:"3118335");
  script_xref(name:"MSKB", value:"3172514");
  script_xref(name:"MSKB", value:"5002140");
  script_xref(name:"MSKB", value:"5002146");
  script_xref(name:"MSFT", value:"MS22-3118335");
  script_xref(name:"MSFT", value:"MS22-3172514");
  script_xref(name:"MSFT", value:"MS22-5002140");
  script_xref(name:"MSFT", value:"MS22-5002146");
  script_xref(name:"IAVA", value:"2022-A-0066-S");

  script_name(english:"Security Updates for Microsoft Office Products (February 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. It is, therefore, affected by multiple vulnerabilities:

  - Two remote code execution vulnerabilities. An attacker can exploit these to bypass authentication and
    execute unauthorized arbitrary commands. (CVE-2022-22003, CVE-2022-22004)

  - An information disclosure vulnerability. An attacker can exploit this to disclose potentially sensitive
    information. (CVE-2022-23252)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/3118335");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/3172514");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002140");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002146");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB3118335
  -KB3172514
  -KB5002140
  -KB5002146

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22003");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var bulletin = 'MS22-02';
var kbs = make_list(
  '3118335',
  '3172514',
  '5002140',
  '5002146'
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

var vuln = FALSE;
var port = kb_smb_transport();

var office_vers = hotfix_check_office_version();

var office_sp, prod, path, kb, file, version;

# Office 2013 SP1
if (office_vers['15.0'])
{
  office_sp = get_kb_item('SMB/Office/2013/SP');
  if (!isnull(office_sp) && office_sp == 1)
  {
    prod = 'Microsoft Office 2013 SP1';

    path = hotfix_get_officecommonfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office15');
    kb = '5002146';
    file = 'mso.dll';
    version = '15.0.5423.1000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;

    path = hotfix_get_officeprogramfilesdir(officever:'15.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office15');
    kb = '3172514';
    file = 'gkexcel.dll';
    version = '15.0.5423.1000';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;
  }
}

# Office 2016
if (office_vers['16.0'])
{
  office_sp = get_kb_item('SMB/Office/2016/SP');
  if (!isnull(office_sp) && office_sp == 0)
  {
    prod = 'Microsoft Office 2016';
    
    # MSI mso.dll
    path = hotfix_get_officecommonfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Shared\\Office16');
    if (hotfix_check_fversion(file:'mso.dll', version:'16.0.5278.1000', channel:'MSI', channel_product:'Office', path:path, kb:'5002140', bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    # MSI gkexcel.dll
    path = hotfix_get_officeprogramfilesdir(officever:'16.0');
    path = hotfix_append_path(path:path, value:'Microsoft Office\\Office16');
    if (hotfix_check_fversion(file:'gkexcel.dll', version:'16.0.5278.1000', channel:'MSI', channel_product:'Office', path:path, kb:'3118335', bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
  }
}


if (vuln)
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
