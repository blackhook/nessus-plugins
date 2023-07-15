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
  script_id(111072);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-0787");
  script_bugtraq_id(103282);

  script_name(english:"Microsoft ASP.NET Core Privilege Escalation (March 2018)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft ASP.NET Core installations on the remote host contain vulnerable packages.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has an installation of ASP.NET Core 
containing the packages HttpOverrides and/or Server.Kestrel.Core with 
versions 2.0.0 or 2.0.1 and therefore is affected by a privilege 
escalation vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/aspnet/Announcements/issues/295");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0787
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eda99e15");
  script_set_attribute(attribute:"solution", value:
"Update HttpOverrides and/or Server.Kestrel.Core to version 2.0.2, 
remove the vulnerable versions and refer to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0787");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:asp.net_core");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

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
include("vcf.inc");

appname = 'ASP .NET Core Windows';
package_dat = {
  'Microsoft.AspNetCore.HttpOverrides':{
    'constraints':[
      { "min_version" : "2.0.0", "fixed_version" : "2.0.2" }
    ],
    'instances':make_list()
  },
  'Microsoft.AspNetCore.Server.Kestrel.Core':{
    'constraints':[
      { "min_version" : "2.0.0", "fixed_version" : "2.0.2" }
    ],
    'instances':make_list()
  }
};

port = kb_smb_transport();

# Only need one install - packages for all installs will be enumerated
install = get_single_install(app_name:appname);
version = install['version'];
path = install['path'];

# Parse extras
foreach package (keys(package_dat))
{
  foreach instance (split(install[package], sep:';', keep:false))
  {
    next = max_index(package_dat[package]['instances']);
    package_dat[package]['instances'][next] = split(instance, sep:'?', keep:false);
  }
}

report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + version +
  '\n';

vuln = false;
foreach package (keys(package_dat))
{
  foreach instance (package_dat[package]['instances'])
  {
    out = vcf::check_version(
      version:vcf::parse_version(instance[0]),
      constraints:package_dat[package]['constraints']
    );
    if (!vcf::is_error(out) && !isnull(out))
    {
      vuln = true;
      report +=
        '\n  Package           : ' + package +
        '\n  Path              : ' + instance[1] +
        '\n  Installed version : ' + instance[0] +
        '\n  Fixed version     : ' + out['fixed_version'] +
        '\n';
    }
  }
}

if (vuln)
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
else
  audit(AUDIT_INST_VER_NOT_VULN, appname);
