#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133049);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-0602", "CVE-2020-0603");
  script_xref(name:"IAVA", value:"2020-A-0027-S");

  script_name(english:"Security Update for Microsoft ASP.NET Core (January 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft ASP.NET Core installations on the remote host contain vulnerable packages.");
  script_set_attribute(attribute:"description", value:
"The Microsoft ASP.NET Core installation on the remote host is version 2.1.x < 2.1.15, 3.0.x < 3.0.2, or 3.1.x < 3.1.1.
It is, therefore, affected by multiple vulnerabilities:

  - A denial of service vulnerability exists when ASP.NET Core improperly handles web requests. An attacker who
    successfully exploited this vulnerability could cause a denial of service against an ASP.NET Core web application.
    The vulnerability can be exploited remotely, without authentication. A remote unauthenticated attacker could
    exploit this vulnerability by issuing specially crafted requests to the ASP.NET Core application. (CVE-2020-0602)

  - A remote code execution vulnerability exists in ASP.NET Core software when the software fails to handle objects in
    memory. An attacker who successfully exploited the vulnerability could run arbitrary code in the context of the
    current user. If the current user is logged on with administrative user rights, an attacker could take control of
    the affected system. An attacker could then install programs; view, change, or delete data; or create new accounts
    with full user rights. Users whose accounts are configured to have fewer user rights on the system could be less
    impacted than users who operate with administrative user rights. (CVE-2020-0603)");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0602
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?530ba67f");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0603
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?374d2043");
  script_set_attribute(attribute:"see_also", value:"https://github.com/aspnet/Announcements/issues/402");
  script_set_attribute(attribute:"see_also", value:"https://github.com/aspnet/Announcements/issues/403");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/aspnetcore/issues/18336");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/aspnetcore/issues/18337");
  script_set_attribute(attribute:"solution", value:
"Update ASP.NET Core, remove vulnerable packages and refer to vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0603");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:asp.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_asp_dotnet_core_win.nbin");
  script_require_keys("installed_sw/ASP .NET Core Windows");
  script_require_ports(139, 445);

  exit(0);
}

include('global_settings.inc');
include('audit.inc');
include('install_func.inc');
include('misc_func.inc');
include('smb_func.inc');
include('vcf.inc');

appname = 'ASP .NET Core Windows';
port = kb_smb_transport();
vuln = FALSE;
install = get_single_install(app_name:appname);

report =
  '\n  Path              : ' + install['path'] +
  '\n  Installed version : ' + install['version'] +
  '\n';

package_dat = {
  'Microsoft.AspNetCore.All':{
    'constraints':[
      { 'min_version' : '2.1.0', 'fixed_version' : '2.1.15' }
    ]
  },
  'Microsoft.AspNetCore.App':{
    'constraints':[
      { 'min_version' : '2.1.0', 'fixed_version' : '2.1.15' },
      { 'min_version' : '3.0.0', 'fixed_version' : '3.0.1' },
      { 'min_version' : '3.1.0', 'fixed_version' : '3.1.1' }
    ]
  },
  'Microsoft.AspNetCore.Http.Connections':{
    'constraints':[
      { 'min_version' : '1.0.0', 'max_version' : '1.0.4', 'fixed_version' : '1.0.15' }
    ]
  }
};

foreach package (keys(package_dat))
{
  foreach instance (split(install[package], sep:';', keep:false))
  {
    inst = split(instance, sep:'?', keep:false);
    out = vcf::check_version(version:vcf::parse_version(inst[0]), constraints:package_dat[package]['constraints']);
    if(!vcf::is_error(out) && !isnull(out))
    {
      vuln = TRUE;
      report +=
        '\n  Package           : ' + package +
        '\n  Path              : ' + inst[1] +
        '\n  Installed version : ' + inst[0] +
        '\n  Fixed version     : ' + out['fixed_version'] +
        '\n';
    }
  }
}

if(!vuln) audit(AUDIT_INST_VER_NOT_VULN, appname + ' ' + install['version']);

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
