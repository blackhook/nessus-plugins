#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128770);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-1302");

  script_name(english:"Security Update for Microsoft ASP.NET Core (Sep 2019)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft ASP.NET Core installations on the remote host contain vulnerable packages.");
  script_set_attribute(attribute:"description", value:
"The Microsoft ASP.NET Core installation on the remote host is version
2.1.x < 2.1.2, or 2.2.x < 2.2.1. It is, therefore, affected by an 
elevation of privilege vulnerability that could lead to a content 
injection attack enabling an attacker to run a script in the 
context of the logged-on user. An unauthenticated, remote attacker 
could exploit this issue, via a link that has a specially crafted URL,
and convince the user to click the link. (CVE-2019-1302)");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1302
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?729669e9");
  # https://github.com/aspnet/Announcements/issues/384
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40f974ac");
  # https://github.com/aspnet/AspNetCore/issues/13859
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5164378b");
  script_set_attribute(attribute:"solution", value:
"Refer to vendor documentation.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1302");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:asp.net_core");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  'Microsoft.AspNetCore.SpaServices':{
    'constraints':[
      { 'min_version' : '2.1.0', 'fixed_version' : '2.1.2' },
      { 'min_version' : '2.2.0', 'fixed_version' : '2.2.1' }
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

security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
