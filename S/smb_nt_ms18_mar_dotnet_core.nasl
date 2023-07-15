#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#
include("compat.inc");

if (description)
{
  script_id(108408);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2018-0875");
  script_bugtraq_id(103225);

  script_name(english:"Security Update for .NET Core (March 2018)");
  script_summary(english:"Checks for Windows Install of .NET Core.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a .NET Core runtime
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has an installation of .NET Core
with a version less than 2.0.6. Therefore, the host is affected
by multiple vulnerabilities.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0875
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0fc5e53");
  # https://github.com/dotnet/core/blob/master/release-notes/2.0/2.0.6.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0803131");
  # https://github.com/dotnet/core/blob/master/release-notes/1.1/1.1.7.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc72caf1");
  # https://github.com/dotnet/core/blob/master/release-notes/1.0/1.0.10.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f659e90");
  script_set_attribute(attribute:"solution", value:
"Update to .NET Core Runtime version 1.10 / 1.1.6 / 2.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0875");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_win.nbin");
  script_require_keys("installed_sw/.NET Core Windows");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("install_func.inc");
include("misc_func.inc");
include("smb_func.inc");

appname = '.NET Core Windows';
port = kb_smb_transport();

installs = get_installs(app_name:appname, exit_if_not_found:TRUE);

report = '';

foreach install (installs[1])
{
  version = install['version'];
  path = install['path'];

  fix = '';
  # Affected: 1.0.x < 1.0.10 / 1.1.x < 1.1.7 / 2.0.x < 2.0.6
  if      (version =~ '^2\\.0\\.') fix = '2.0.6.26212';
  else if (version =~ '^1\\.1\\.') fix = '1.1.7.1667';
  else if (version =~ '^1\\.0\\.') fix = '1.0.10.5023';

  if (fix != '' && ver_compare(ver:version, fix:fix) < 0)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
  }
}

if (report != '')
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
else 
  audit(AUDIT_INST_VER_NOT_VULN, appname);
