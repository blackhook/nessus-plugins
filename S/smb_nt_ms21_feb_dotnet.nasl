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
  script_id(168396);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2021-24111");
  script_xref(name:"MSKB", value:"4578950");
  script_xref(name:"MSKB", value:"4578951");
  script_xref(name:"MSKB", value:"4578952");
  script_xref(name:"MSKB", value:"4578953");
  script_xref(name:"MSKB", value:"4600944");
  script_xref(name:"MSKB", value:"4600945");
  script_xref(name:"MSKB", value:"4600957");
  script_xref(name:"MSKB", value:"4601048");
  script_xref(name:"MSKB", value:"4601050");
  script_xref(name:"MSKB", value:"4601051");
  script_xref(name:"MSKB", value:"4601052");
  script_xref(name:"MSKB", value:"4601054");
  script_xref(name:"MSKB", value:"4601055");
  script_xref(name:"MSKB", value:"4601056");
  script_xref(name:"MSKB", value:"4601057");
  script_xref(name:"MSKB", value:"4601058");
  script_xref(name:"MSKB", value:"4601060");
  script_xref(name:"MSKB", value:"4601089");
  script_xref(name:"MSKB", value:"4601090");
  script_xref(name:"MSKB", value:"4601091");
  script_xref(name:"MSKB", value:"4601092");
  script_xref(name:"MSKB", value:"4601093");
  script_xref(name:"MSKB", value:"4601094");
  script_xref(name:"MSFT", value:"MS21-4578950");
  script_xref(name:"MSFT", value:"MS21-4578951");
  script_xref(name:"MSFT", value:"MS21-4578952");
  script_xref(name:"MSFT", value:"MS21-4578953");
  script_xref(name:"MSFT", value:"MS21-4600944");
  script_xref(name:"MSFT", value:"MS21-4600945");
  script_xref(name:"MSFT", value:"MS21-4600957");
  script_xref(name:"MSFT", value:"MS21-4601048");
  script_xref(name:"MSFT", value:"MS21-4601050");
  script_xref(name:"MSFT", value:"MS21-4601051");
  script_xref(name:"MSFT", value:"MS21-4601052");
  script_xref(name:"MSFT", value:"MS21-4601054");
  script_xref(name:"MSFT", value:"MS21-4601055");
  script_xref(name:"MSFT", value:"MS21-4601056");
  script_xref(name:"MSFT", value:"MS21-4601057");
  script_xref(name:"MSFT", value:"MS21-4601058");
  script_xref(name:"MSFT", value:"MS21-4601060");
  script_xref(name:"MSFT", value:"MS21-4601089");
  script_xref(name:"MSFT", value:"MS21-4601090");
  script_xref(name:"MSFT", value:"MS21-4601091");
  script_xref(name:"MSFT", value:"MS21-4601092");
  script_xref(name:"MSFT", value:"MS21-4601093");
  script_xref(name:"MSFT", value:"MS21-4601094");
  script_xref(name:"IAVA", value:"2021-A-0079-S");

  script_name(english:"Security Updates for Microsoft .NET Framework (February 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Framework installation on the remote host is missing a security update. It is, therefore, affected
by a denial of service vulnerability.");
  # https://devblogs.microsoft.com/dotnet/net-framework-february-security-and-quality-rollup/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3bc4c23");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-24111
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?062350f4");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4578950");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4578951");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4578952");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4578953");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4600944");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4600945");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4600957");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4601048");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4601050");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4601051");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4601052");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4601054");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4601055");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4601056");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4601057");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4601058");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4601060");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4601089");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4601090");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4601091");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4601092");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4601093");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4601094");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released security updates for Microsoft .NET Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-24111");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
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
  '4578950',
  '4578951',
  '4578952',
  '4578953',
  '4600944',
  '4600945',
  '4600957',
  '4601048',
  '4601050',
  '4601051',
  '4601052',
  '4601054',
  '4601055',
  '4601056',
  '4601057',
  '4601058',
  '4601060',
  '4601089',
  '4601090',
  '4601091',
  '4601092',
  '4601093',
  '4601094'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2' , win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

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
        smb_check_dotnet_rollup(rollup_date:'02_2021', dotnet_ver:version))
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
