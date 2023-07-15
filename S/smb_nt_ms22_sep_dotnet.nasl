#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(168398);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2022-26929");
  script_xref(name:"MSKB", value:"5017022");
  script_xref(name:"MSKB", value:"5017024");
  script_xref(name:"MSKB", value:"5017025");
  script_xref(name:"MSKB", value:"5017028");
  script_xref(name:"MSKB", value:"5017029");
  script_xref(name:"MSKB", value:"5017030");
  script_xref(name:"MSFT", value:"MS22-5017022");
  script_xref(name:"MSFT", value:"MS22-5017024");
  script_xref(name:"MSFT", value:"MS22-5017025");
  script_xref(name:"MSFT", value:"MS22-5017028");
  script_xref(name:"MSFT", value:"MS22-5017029");
  script_xref(name:"MSFT", value:"MS22-5017030");
  script_xref(name:"IAVA", value:"2022-A-0376-S");

  script_name(english:"Security Updates for Microsoft .NET Framework (September 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update. It is, therefore, affected
by a remote code execution vulnerability.");
  # https://devblogs.microsoft.com/dotnet/dotnet-framework-september-2022-security-and-quality-rollup/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8867409d");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-26929
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bfadca4c");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5017022");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5017024");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5017025");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5017028");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5017029");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5017030");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26929");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_dotnet_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_net_framework_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('install_func.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

var bulletin = 'MS21-02';
var kbs = make_list(
  '5017022',
  '5017024',
  '5017025',
  '5017028',
  '5017029',
  '5017030'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
var windows_version = get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);
var windows_build = get_kb_item_or_exit('SMB/WindowsVersionBuild', exit_code:1);

if (windows_version != 10 || windows_build < 19042)
  exit(0, '.NET update contained in Windows Rollup');

var share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

var app = 'Microsoft .NET Framework';
get_install_count(app_name:app, exit_if_zero:TRUE);
var installs = get_combined_installs(app_name:app);

var install, version;
var vuln = 0;

if (installs[0] == 0)
{
  foreach install (installs[1])
  {
    version = install['version'];
    if( version != UNKNOWN_VER &&
        smb_check_dotnet_rollup(rollup_date:'09_2022', dotnet_ver:version))
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
