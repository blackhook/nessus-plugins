#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108407);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-0808");
  script_bugtraq_id(103226);

  script_name(english:"Security Update for ASP.NET Core (March 2018)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an ASP.NET Core
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has an installation of ASP.NET Core SDK
with a version of aspnetcore.dll less than 7.1.1990.0. Therefore, 
the host is affected by a Denial of Service vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/aspnet/Announcements/issues/294");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0808
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c744cbb9");
  script_set_attribute(attribute:"solution", value:
"Update to ASP.NET Core Hosting Bundle 1.0.10 / 1.1.7 / 2.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0808");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:asp.net_core");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_asp_dotnet_core_win.nbin");
  script_require_keys("installed_sw/ASP .NET Core Windows");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("install_func.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

appname = 'ASP .NET Core Windows';
port = kb_smb_transport();

installs = get_installs(app_name:appname, exit_if_not_found:TRUE);

report = '';

fix = '7.1.1990.0';

if ( hcf_init == 0 )
{
  if(hotfix_check_fversion_init() != HCF_OK)
    exit(0, "Could not start an SMB session");
}

windows = hotfix_get_systemroot();

dll_path = hotfix_append_path(path:windows, value:"\\System32\\inetsrv\\aspnetcore.dll");

if (hotfix_file_exists(path:dll_path))
{
  fver = hotfix_get_fversion(path:dll_path);

  if (fver['error'] != HCF_OK)
  {
    hotfix_check_fversion_end();
    audit(AUDIT_FN_FAIL, 'hotfix_get_fversion');
  }
  dll_ver = join(fver['value'], sep:'.');

  if (ver_compare(ver:dll_ver, fix:fix) < 0)
  {
    report =
      '\n  Path              : ' + dll_path +
      '\n  Installed version : ' + dll_ver +
      '\n  Fixed version     : ' + fix +
      '\n';
  }
}
hotfix_check_fversion_end();

if (report != '')
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
else 
  audit(AUDIT_INST_VER_NOT_VULN, appname);
