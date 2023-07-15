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
  script_id(118149);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-8292");

  script_name(english:"Security Update for .NET Core SDK (October 2018)");
  script_summary(english:"Checks for Windows Install of .NET Core.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a .NET Core SDK
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has an installation of .NET Core
SDK with a version less than 1.1.11 Therefore, the host is 
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/announcements/issues/88");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8292
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2a4a4fff");
  script_set_attribute(attribute:"solution", value:
"Update to .NET Core SDK version 1.1.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8292");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_sdk_win.nbin");
  script_require_keys("installed_sw/.NET Core SDK Windows", "Settings/ParanoidReport");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("install_func.inc");
include("misc_func.inc");

appname = '.NET Core SDK Windows';

get_kb_item_or_exit("installed_sw/.NET Core SDK Windows");
if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("SMB/transport");
if(port) port = int(port);
else port = 445;

installs = get_installs(app_name:appname, exit_if_not_found:TRUE);

foreach install (installs[1])
{
  version = install['version'];
  path = install['path'];
  fix = "1.1.11";

  if (version =~ "^1\." && ver_compare(ver:version, fix:fix,strict:FALSE) < 0)
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
}

if(empty_or_null(report))
  audit(AUDIT_INST_VER_NOT_VULN, appname);

security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
