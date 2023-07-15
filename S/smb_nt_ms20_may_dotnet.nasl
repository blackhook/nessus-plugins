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
  script_id(136564);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/30");

  script_cve_id("CVE-2020-1066", "CVE-2020-1108");
  script_xref(name:"MSKB", value:"4556812");
  script_xref(name:"MSKB", value:"4556826");
  script_xref(name:"MSKB", value:"4556807");
  script_xref(name:"MSKB", value:"4556813");
  script_xref(name:"MSKB", value:"4556406");
  script_xref(name:"MSKB", value:"4556405");
  script_xref(name:"MSKB", value:"4556404");
  script_xref(name:"MSKB", value:"4556403");
  script_xref(name:"MSKB", value:"4556402");
  script_xref(name:"MSKB", value:"4556401");
  script_xref(name:"MSKB", value:"4556400");
  script_xref(name:"MSKB", value:"4556441");
  script_xref(name:"MSKB", value:"4552926");
  script_xref(name:"MSKB", value:"4552931");
  script_xref(name:"MSKB", value:"4556399");
  script_xref(name:"MSKB", value:"4552928");
  script_xref(name:"MSKB", value:"4552929");
  script_xref(name:"MSFT", value:"MS20-4556812");
  script_xref(name:"MSFT", value:"MS20-4556826");
  script_xref(name:"MSFT", value:"MS20-4556807");
  script_xref(name:"MSFT", value:"MS20-4556813");
  script_xref(name:"MSFT", value:"MS20-4556406");
  script_xref(name:"MSFT", value:"MS20-4556405");
  script_xref(name:"MSFT", value:"MS20-4556404");
  script_xref(name:"MSFT", value:"MS20-4556403");
  script_xref(name:"MSFT", value:"MS20-4556402");
  script_xref(name:"MSFT", value:"MS20-4556401");
  script_xref(name:"MSFT", value:"MS20-4556400");
  script_xref(name:"MSFT", value:"MS20-4556441");
  script_xref(name:"MSFT", value:"MS20-4552926");
  script_xref(name:"MSFT", value:"MS20-4552931");
  script_xref(name:"MSFT", value:"MS20-4556399");
  script_xref(name:"MSFT", value:"MS20-4552928");
  script_xref(name:"MSFT", value:"MS20-4552929");
  script_xref(name:"IAVA", value:"2020-A-0207-S");

  script_name(english:"Security Updates for Microsoft .NET Framework (May 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - A denial of service vulnerability exists when .NET Core
    or .NET Framework improperly handles web requests. An
    attacker who successfully exploited this vulnerability
    could cause a denial of service against a .NET Core or
    .NET Framework web application. The vulnerability can be
    exploited remotely, without authentication. A remote
    unauthenticated attacker could exploit this
    vulnerability by issuing specially crafted requests to
    the .NET Core or .NET Framework application. The update
    addresses the vulnerability by correcting how the .NET
    Core or .NET Framework web application handles web
    requests. (CVE-2020-1108)

  - An elevation of privilege vulnerability exists in .NET
    Framework which could allow an attacker to elevate their
    privilege level.  (CVE-2020-1066)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4556406/kb4556406");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4556405/kb4556405");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4556404/kb4556404");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4556403/kb4556403");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4556402/kb4556402");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4556401/kb4556401");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4556400/kb4556400");
  # https://support.microsoft.com/en-us/help/4556441/kb4556441-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a2bc4ce");
  # https://support.microsoft.com/en-us/help/4556813/windows-10-update-kb4556813
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da286489");
  # https://support.microsoft.com/en-us/help/4556807/windows-10-update-kb4556807
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8217353");
  # https://support.microsoft.com/en-us/help/4552926/kb4552926-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a03f407");
  # https://support.microsoft.com/en-us/help/4556826/windows-10-update-kb4556826
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22034bc1");
  # https://support.microsoft.com/en-us/help/4552931/kb4552931-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6206e249");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4556399/kb4556399");
  # https://support.microsoft.com/en-us/help/4556812/windows-10-update-kb4556812
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?229bf576");
  # https://support.microsoft.com/en-us/help/4552928/kb4552928-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52b55515");
  # https://support.microsoft.com/en-us/help/4552929/kb4552929-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4aafe901");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1066");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

bulletin = 'MS20-05';
kbs = make_list(
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

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
        smb_check_dotnet_rollup(rollup_date:'05_2020', dotnet_ver:version))
      vuln++;
  }
}
if(vuln)
{
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

