#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc. 
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156745);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/11");

  script_cve_id("CVE-2022-21846", "CVE-2022-21855", "CVE-2022-21969");
  script_xref(name:"MSKB", value:"5008631");
  script_xref(name:"MSFT", value:"MS22-5008631");
  script_xref(name:"IAVA", value:"2022-A-0009-S");

  script_name(english:"Security Updates for Exchange (January 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host is missing security updates. It is, therefore, affected by
a remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute unauthorized
arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5008631");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB5008631 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21846");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_exchange_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('install_func.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

exit_if_productname_not_server();

var bulletin = 'MS22-01';
var kbs = make_list(
  '5008631'
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

var install = get_single_install(app_name:'Microsoft Exchange');

var path = install['path'];
var version = install['version'];
var release = install['RELEASE'];
var port = kb_smb_transport();

if (
    release != 150 &&  # 2013
    release != 151 &&  # 2016
    release != 152     # 2019
)  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);

var kb_checks =
{
  '150' :
    {
      '23' : '15.00.1497.028',
      'unsupported' : 22
    },
  '151' :
    {
      '21' : '15.01.2308.021',
      '22' : '15.01.2375.018',
      'unsupported' : 20
    },
  '152' :
    {
      '10' : '15.02.0922.020',
      '11' : '15.02.0986.015',
      'unsupported' : 9}
};

var cu = 0;
if (!empty_or_null(install['CU']))
  cu = install['CU'];
var kb = '5008631';
var unsupported = FALSE;

if (kb_checks[release]['unsupported'] >= cu) unsupported_cu = TRUE;
  else if (empty_or_null(kb_checks[release][cu])) audit(AUDIT_HOST_NOT, 'affected');


var fixedver = kb_checks[release][cu];

if ((fixedver && hotfix_is_vulnerable(path:hotfix_append_path(path:path, value:"Bin"), file:'ExSetup.exe', version:fixedver, bulletin:bulletin, kb:kb))
  || (unsupported_cu && report_paranoia == 2))
{
  if (unsupported_cu)
    hotfix_add_report('The Microsoft Exchange Server installed at ' + path +
    ' has an unsupported Cumulative Update (CU) installed and may be ' +
    'vulnerable to the CVEs contained within the advisory. Unsupported ' +
    'Exchange CU versions are not typically included in Microsoft ' +
    'advisories and are not indicated as affected.\n',
    bulletin:bulletin, kb:kb);

  set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
