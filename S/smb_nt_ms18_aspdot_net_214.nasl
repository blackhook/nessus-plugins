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
  script_id(105796);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/07");

  script_cve_id("CVE-2018-0784", "CVE-2018-0785");
  script_bugtraq_id(102377, 102379);

  script_name(english:"Security Update for ASP.NET Core January 2018");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple ASP.NET Core 
runtime vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has an installation of ASP.NET Core and .NET 
Core SDK with a version less than 2.1.4. Therefore, the host is affected 
by multiple vulnerabilities:
                                                                      
  - An elevation of privilege vulnerability due to
    improper sanitization of web requests (CVE-2018-0784)

  - A cross-site request forgery that could allow
    an attacker to change the recovery codes of a
    victims account. (CVE-2018-0785)");
  script_set_attribute(attribute:"see_also", value:"https://github.com/aspnet/Announcements/issues/284");
  script_set_attribute(attribute:"see_also", value:"https://github.com/aspnet/Announcements/issues/285");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0784
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af8d6135");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0785
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?efd30f91");
  script_set_attribute(attribute:"solution", value:
"Update to .NET Core SDK version 2.1.4 or later and refer to vendor 
advisory for any template-generated ASP.NET Core web applications.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0784");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:asp.net_core");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_sdk_win.nbin", "microsoft_asp_dotnet_core_win.nbin");
  script_require_keys("installed_sw/.NET Core SDK Windows", "installed_sw/ASP .NET Core Windows");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("install_func.inc");
include("misc_func.inc");
include("smb_func.inc");

appname_sdk = '.NET Core SDK Windows';
port = kb_smb_transport();

get_kb_item_or_exit("installed_sw/ASP .NET Core Windows");
installs_sdk = get_installs(app_name:appname_sdk, exit_if_not_found:TRUE);

report = '';

foreach install (installs_sdk[1])
{
  version = install['version'];
  path = install['path'];

  fix = '2.1.4.0';
  # Affected: 2.0.0, 2.0.2, 2.0.3, 2.1.2, 2.1.3
  # Note that there is no versions 2.0.1/2.0.4/etc of the SDK
  if (version =~ "^2\." && ver_compare(ver:version, fix:fix) < 0)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
  }
}

if (report != '')
{
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report, xsrf:TRUE);
  exit(0);
}

audit(AUDIT_INST_VER_NOT_VULN, appname_sdk, version);
