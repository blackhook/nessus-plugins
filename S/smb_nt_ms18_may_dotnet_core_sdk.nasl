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
  script_id(109732);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-0765");
  script_bugtraq_id(104060);

  script_name(english:"Security Update for .NET Core SDK (May 2018)");
  script_summary(english:"Checks for Windows Install of .NET Core.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a .NET Core SDK
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has an installation of .NET Core
SDK with a version less than 2.1.200.0. Therefore, the host is 
affected by a denial of service vulnerability.");
  # https://github.com/dotnet/core/blob/master/release-notes/2.0/2.1.200-sdk.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?802de2b2");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/announcements/issues/67");
  script_set_attribute(attribute:"solution", value:
"Update to .NET Core SDK version 2.1.200 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0765");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_sdk_win.nbin");
  script_require_keys("installed_sw/.NET Core SDK Windows");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("install_func.inc");
include("misc_func.inc");
include("smb_func.inc");

appname = '.NET Core SDK Windows';
port = kb_smb_transport();

installs = get_installs(app_name:appname, exit_if_not_found:TRUE);
if (report_paranoia < 2) audit(AUDIT_PARANOID);
report = '';

foreach install (installs[1])
{
  version = install['version'];
  path = install['path'];
  fix = '2.1.200.0';

  if (version =~ "^2\." && ver_compare(ver:version, fix:fix,strict:FALSE) < 0)
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
