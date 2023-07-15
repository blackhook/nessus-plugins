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
  script_id(138464);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-1147");
  script_xref(name:"IAVA", value:"2020-A-0305-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"MSKB", value:"4565489");
  script_xref(name:"MSKB", value:"4565508");
  script_xref(name:"MSKB", value:"4565511");
  script_xref(name:"MSKB", value:"4565513");
  script_xref(name:"MSKB", value:"4565627");
  script_xref(name:"MSKB", value:"4565628");
  script_xref(name:"MSKB", value:"4565630");
  script_xref(name:"MSKB", value:"4565631");
  script_xref(name:"MSKB", value:"4565633");
  script_xref(name:"MSKB", value:"4566466");
  script_xref(name:"MSKB", value:"4566467");
  script_xref(name:"MSKB", value:"4566468");
  script_xref(name:"MSKB", value:"4566469");
  script_xref(name:"MSKB", value:"4566516");
  script_xref(name:"MSKB", value:"4566517");
  script_xref(name:"MSKB", value:"4566518");
  script_xref(name:"MSKB", value:"4566519");
  script_xref(name:"MSKB", value:"4566520");
  script_xref(name:"MSFT", value:"MS20-4565489");
  script_xref(name:"MSFT", value:"MS20-4565508");
  script_xref(name:"MSFT", value:"MS20-4565511");
  script_xref(name:"MSFT", value:"MS20-4565513");
  script_xref(name:"MSFT", value:"MS20-4565627");
  script_xref(name:"MSFT", value:"MS20-4565628");
  script_xref(name:"MSFT", value:"MS20-4565630");
  script_xref(name:"MSFT", value:"MS20-4565631");
  script_xref(name:"MSFT", value:"MS20-4565633");
  script_xref(name:"MSFT", value:"MS20-4566466");
  script_xref(name:"MSFT", value:"MS20-4566467");
  script_xref(name:"MSFT", value:"MS20-4566468");
  script_xref(name:"MSFT", value:"MS20-4566469");
  script_xref(name:"MSFT", value:"MS20-4566516");
  script_xref(name:"MSFT", value:"MS20-4566517");
  script_xref(name:"MSFT", value:"MS20-4566518");
  script_xref(name:"MSFT", value:"MS20-4566519");
  script_xref(name:"MSFT", value:"MS20-4566520");

  script_name(english:"Security Updates for Microsoft .NET Framework (July 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host
is missing a security update. It is, therefore, affected by
the following vulnerability :

  - A remote code execution vulnerability exists in .NET
    Framework, Microsoft SharePoint, and Visual Studio when
    the software fails to check the source markup of XML
    file input. An attacker who successfully exploited the
    vulnerability could run arbitrary code in the context of
    the process responsible for deserialization of the XML
    content.  (CVE-2020-1147)");
  # https://support.microsoft.com/en-us/help/4566516/kb4566516-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e394aff7");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4566469/kb4566469");
  # https://support.microsoft.com/en-us/help/4565508/windows-10-update-kb4565508
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2aadf5b");
  # https://support.microsoft.com/en-us/help/4565630/kb4565630-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78bdeafd");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4566468/kb4566468");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4566519/kb4566519");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4566466/kb4566466");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4566517/kb4566517");
  # https://support.microsoft.com/en-us/help/4565513/windows-10-update-kb4565513
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0366a03");
  # https://support.microsoft.com/en-us/help/4565511/windows-10-update-kb4565511
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?777905a0");
  # https://support.microsoft.com/en-us/help/4565489/windows-10-update-kb4565489
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6e77e0f");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4566518/kb4566518");
  # https://support.microsoft.com/en-us/help/4565627/kb4565627-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?625a0a16");
  # https://support.microsoft.com/en-us/help/4565628/kb4565628-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?822e3925");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4566520/kb4566520");
  # https://support.microsoft.com/en-us/help/4565633/kb4565633-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8bc61313");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4566467/kb4566467");
  # https://support.microsoft.com/en-us/help/4565631/kb4565631-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a5f0660");
  # https://support.microsoft.com/en-us/help/4566516/kb4566516-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e394aff7");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4566469/kb4566469");
  # https://support.microsoft.com/en-us/help/4565508/windows-10-update-kb4565508
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2aadf5b");
  # https://support.microsoft.com/en-us/help/4565630/kb4565630-cumulative-update-for-net-framework
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78bdeafd");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4566468/kb4566468");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4566519/kb4566519");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4566466/kb4566466");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4566517/kb4566517");
  # https://support.microsoft.com/en-us/help/4565513/windows-10-update-kb4565513
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0366a03");
  # https://support.microsoft.com/en-us/help/4565511/windows-10-update-kb4565511
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?777905a0");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1147");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SharePoint DataSet / DataTable Deserialization');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/14");

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

bulletin = 'MS20-07';
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
        smb_check_dotnet_rollup(rollup_date:'07_2020', dotnet_ver:version))
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


