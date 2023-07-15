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
  script_id(132999);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-0605", "CVE-2020-0606", "CVE-2020-0646");
  script_xref(name:"MSKB", value:"4532935");
  script_xref(name:"MSKB", value:"4535101");
  script_xref(name:"MSKB", value:"4535103");
  script_xref(name:"MSKB", value:"4535102");
  script_xref(name:"MSKB", value:"4535105");
  script_xref(name:"MSKB", value:"4535104");
  script_xref(name:"MSKB", value:"4532933");
  script_xref(name:"MSKB", value:"4534271");
  script_xref(name:"MSKB", value:"4532938");
  script_xref(name:"MSKB", value:"4534306");
  script_xref(name:"MSKB", value:"4534977");
  script_xref(name:"MSKB", value:"4534976");
  script_xref(name:"MSKB", value:"4532936");
  script_xref(name:"MSKB", value:"4534276");
  script_xref(name:"MSKB", value:"4534293");
  script_xref(name:"MSKB", value:"4534979");
  script_xref(name:"MSKB", value:"4534978");
  script_xref(name:"MSFT", value:"MS20-4532935");
  script_xref(name:"MSFT", value:"MS20-4535101");
  script_xref(name:"MSFT", value:"MS20-4535103");
  script_xref(name:"MSFT", value:"MS20-4535102");
  script_xref(name:"MSFT", value:"MS20-4535105");
  script_xref(name:"MSFT", value:"MS20-4535104");
  script_xref(name:"MSFT", value:"MS20-4532933");
  script_xref(name:"MSFT", value:"MS20-4534271");
  script_xref(name:"MSFT", value:"MS20-4532938");
  script_xref(name:"MSFT", value:"MS20-4534306");
  script_xref(name:"MSFT", value:"MS20-4534977");
  script_xref(name:"MSFT", value:"MS20-4534976");
  script_xref(name:"MSFT", value:"MS20-4532936");
  script_xref(name:"MSFT", value:"MS20-4534276");
  script_xref(name:"MSFT", value:"MS20-4534293");
  script_xref(name:"MSFT", value:"MS20-4534979");
  script_xref(name:"MSFT", value:"MS20-4534978");
  script_xref(name:"IAVA", value:"2020-A-0028-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Security Updates for Microsoft .NET Framework (January 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - A remote code execution vulnerability exists when the
    Microsoft .NET Framework fails to validate input
    properly. An attacker who successfully exploited this
    vulnerability could take control of an affected system.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights. Users whose accounts are configured to have
    fewer user rights on the system could be less impacted
    than users who operate with administrative user rights.
    (CVE-2020-0646)

  - A remote code execution vulnerability exists in .NET
    software when the software fails to check the source
    markup of a file. An attacker who successfully exploited
    the vulnerability could run arbitrary code in the
    context of the current user. If the current user is
    logged on with administrative user rights, an attacker
    could take control of the affected system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    (CVE-2020-0605, CVE-2020-0606)");
  # https://support.microsoft.com/en-us/help/4532935/kb4532935-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?71a4b34c");
  # https://support.microsoft.com/en-us/help/4535101/kb4535101-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dd1d619");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4535103/kb4535103");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4535102/kb4535102");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4535105/kb4535105");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4535104/kb4535104");
  # https://support.microsoft.com/en-us/help/4532933/kb4532933-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6758a7c");
  # https://support.microsoft.com/en-us/help/4534271/windows-10-update-kb4534271
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e147f537");
  # https://support.microsoft.com/en-us/help/4532938/kb4532938-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f331705");
  # https://support.microsoft.com/en-us/help/4534306/windows-10-update-kb4534306
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fd98f0c");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4534977/kb4534977");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4534976/kb4534976");
  # https://support.microsoft.com/en-us/help/4532936/kb4532936-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bff0836");
  # https://support.microsoft.com/en-us/help/4534276/windows-10-update-kb4534276
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c9c3e46");
  # https://support.microsoft.com/en-us/help/4534293/windows-10-update-kb4534293
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56c0e39b");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4534979/kb4534979");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4534978/kb4534978");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0646");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SharePoint Workflows XOML Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_dotnet_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_net_framework_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('install_func.inc');
include('misc_func.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS20-01';
kbs = make_list(
  '4532935',
  '4535101',
  '4535103',
  '4535102',
  '4535105',
  '4535104',
  '4532933',
  '4534271',
  '4532938',
  '4534306',
  '4534977',
  '4534976',
  '4532936',
  '4534276',
  '4534293',
  '4534979',
  '4534978'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit('SMB/ProductName', exit_code:1);
if ('Windows 8' >< productname && 'Windows 8.1' >!< productname) audit(AUDIT_OS_SP_NOT_VULN);
else if ('Vista' >< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

app = 'Microsoft .NET Framework';
get_install_count(app_name:app, exit_if_zero:TRUE);
installs = get_combined_installs(app_name:app);

vuln = 0;

if (installs[0] == 0)
{
  foreach install (installs[1])
  {
    version = install['version'];
    if( version != UNKNOWN_VER &&
        smb_check_dotnet_rollup(rollup_date:'01_2020', dotnet_ver:version))
      vuln++;
  }
}
if(vuln)
{
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

