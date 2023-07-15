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
  script_id(104665);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-11879", "CVE-2017-11883");
  script_bugtraq_id(101713, 101835);

  script_name(english:"Security Update ASP .NET Core September 2017");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an ASP.NET Core runtime
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has an installation of ASP.NET Core
runtime package store with a version less than 2.0.12219.0.
Therefore the host is affected by multiple vulnerabilities :

  -  An open redirect vulnerability
     that can lead to an escalation of privilege.
     (CVE-2017-11879)

  -  A flaw that is triggered as web requests are not properly
     handled. This may allow a context-dependent attacker to cause
     a denial of service.
     (CVE-2017-11883)");
  script_set_attribute(attribute:"see_also", value:"https://github.com/aspnet/announcements/issues/278");
  script_set_attribute(attribute:"see_also", value:"https://github.com/aspnet/announcements/issues/277");
  # https://download.microsoft.com/download/5/C/1/5C190037-632B-443D-842D-39085F02E1E8/AspNetCore.2.0.3.RuntimePackageStore_x64.exe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76216cca");
  # https://download.microsoft.com/download/5/C/1/5C190037-632B-443D-842D-39085F02E1E8/AspNetCore.2.0.3.RuntimePackageStore_x86.exe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c82bcb0e");
  script_set_attribute(attribute:"solution", value:
"Download and update ASP .NET Core 2.0.3 runtime packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11879");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS17-11";
appname = 'ASP .NET Core Windows';
port = kb_smb_transport();

get_install_count(app_name:appname, exit_if_zero:TRUE);
install  = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
fix_ver = "2.0.12219.0";
version = install['version'];

if(ver_compare(ver: version, fix:fix_ver) < 0)
{
  report =
    '\n  Path              : ' + install['path'] +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix_ver +
    '\n';

  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
  exit(0);
}

audit(AUDIT_INST_VER_NOT_VULN, appname, version);
