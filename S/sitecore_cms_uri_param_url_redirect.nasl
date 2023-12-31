#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55979);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(48930);

  script_name(english:"Sitecore CMS < 6.4.1 rev.110720 'url' Parameter URI Redirection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by a
redirection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Sitecore CMS which is
reportedly affected by a redirection vulnerability. An attacker could
exploit this to redirect users to unintended websites.");
  # https://sdn.sitecore.net/sdn5/misc/loginpage.aspx?item=%2fproducts%2fsitecore+v5%2fsitecore+cms+6%2freleasenotes%2fchangelog%2frelease+history+sc64&user=extranet%5cAnonymous&login=%2fsdn5%2fmisc%2floginpage.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c2f45d7");
  script_set_attribute(attribute:"see_also", value:"http://www.tomneaves.com/Sitecore_CMS_Open_URL_Redirect.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sitecore 6.4.1 rev.110720 or newer.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sitecore:cms");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2022 Tenable Network Security, Inc.");

  script_dependencies("sitecore_cms_detect.nasl");
  script_require_keys("www/sitecore_cms");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80, embedded: 0);
install = get_install_from_kb(appname:"sitecore_cms", port:port, exit_on_fail:TRUE);

verstr = install['ver'];
version = verstr - (substr(verstr, stridx(verstr, ' rev.')));
revision = substr(verstr, stridx(verstr, ' rev.'));
revision = revision - ' rev. ';
rev = int(revision);

if(
  version =~ "^[0-5](\.|$)"    ||
  version =~ "^6\.[0-3](\.|$)" ||
  version =~ "^6\.4\.0$"       ||
  (
    version =~ "^6\.4\.1$" && rev < 110720
  )
)
{
  if(report_verbosity > 0)
  {
    report =
      '\n' +
      '    URL               : ' + build_url(port:port, qs:install['dir']) + '\n' +
      '    Installed version : ' + version + ' rev.' + rev + '\n' +
      '    Fixed version     : 6.4.1 rev.110720\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit();
} else exit(0, "The remote Sitecore CMS install version "+version+" rev. "+rev+" is not affected.");

