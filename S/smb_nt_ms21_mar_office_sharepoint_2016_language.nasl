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
  script_id(164177);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2021-24104");
  script_xref(name:"MSKB", value:"4493199");
  script_xref(name:"MSFT", value:"MS21-4493199");

  script_name(english:"Language Security Updates Security Updates for Microsoft Sharepoint 2016 (March 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server 2016 installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server 2016 installation on the remote host is missing language security updates. It is, therefore,
affected by Microsoft SharePoint Spoofing Vulnerability (CVE-2021-24104)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4493199");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB4493199");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-24104");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_sharepoint_installed.nbin", "smb_language_detection.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "SMB/base_language_installs");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

var bulletin = 'MS21-03';
var app_name = 'Microsoft SharePoint Server';

var kbs = make_list(
  '4493199'
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

var all_language_lists = get_kb_list('SMB/base_language_installs');
if (isnull(all_language_lists)) exit(1, 'Language File Scan Information not found');

all_language_lists = make_list(all_language_lists);

var item;
var language_lists = [];
if (!empty_or_null(all_language_lists))
{
  foreach item (all_language_lists)
  {
    # English and Spanish (Mexico) contain an older version of wwintl.dll
    if (item == "1033" || item == "2058") continue;
    append_element(var:language_lists, value:item);
  }
}
if (isnull(language_lists)) exit(1, 'No Affected Language Packs were found');

# Get path information for Windows.
var windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, 'Failed to determine the location of %windir%.');

registry_init();
var install = get_single_install(app_name:app_name);

var kb_checks =
{
  '2016':
  { '0':
    {'Server':
      [
        {
          'kb'           : '4493199',
          'path'         : install['path'],
          'append'       : 'webservices\\conversionservices\\*',
          'file'         : 'wwintl.dll',
          'version'      : '16.0.5134.1000',
          'product_name' : 'Microsoft SharePoint Enterprise Server 2016'
        }
      ]
    }
  }
};

# Get the specific product / path
var param_list = kb_checks[install['Product']][install['SP']][install['Edition']];
# audit if not affected
if(isnull(param_list)) audit(AUDIT_HOST_NOT, 'affected');
var port = kb_smb_transport();
var check, path, path_list, are_we_vuln, report;
# grab the path otherwise

foreach check (param_list)
{
  if (!isnull(check['version']))
  {
    path = check['path'];
    path_list = hotfix_append_path(path:check['path'], value:check['append']);
    path_list = language_pack_iterate(language_lists:language_lists, file_directory:path_list);

    are_we_vuln = hotfix_check_fversion_multipath(
    file_name:check['file'],
    version:check['version'],
    path_list:path_list,
    kb:check['kb'],
    product:check['product_name']
    );
  }
}

if (are_we_vuln == HCF_OLDER) vuln = TRUE;

if (vuln)
{
  port = kb_smb_transport();
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else if (!vuln)
{
  hotfix_check_fversion_end();
  audit(AUDIT_INST_VER_NOT_VULN, app_name);
}
