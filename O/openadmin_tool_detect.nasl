#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56171);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"OpenAdmin Tool Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a database management application
written in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts OpenAdmin Tool for Informix (OAT), a PHP-
based administration tool for managing Informix database servers.");
  script_set_attribute(attribute:"see_also", value:"http://openadmintool.org/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:openadmin_tool");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:8080, php:TRUE, embedded:FALSE);


# Loop through directories.
#
# nb: '/openadmin' is used by default so we'll always try that.
dirs = list_uniq(make_list("/openadmin", cgi_dirs()));

foreach dir (dirs)
{
  url = dir + '/index.php?act=help&do=aboutOAT';
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (
    "formright'> OpenAdmin Tool" >< res[2] ||
    '>Open Admin Tool for IDS - Version:' >< res[2] ||
    '>OpenAdmin Tool - Version:' >< res[2]
  )
  {
    version = NULL;

    pat = '>(OpenAdmin Tool|Open Admin Tool for IDS) - Version: ([0-9]+\\.[^<]+)<';
    matches = egrep(pattern:pat, string:res[2]);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          version = item[2];
          break;
        }
      }
    }

    if (
      isnull(version) &&
      ">Version: </td>" >< res[2] &&
      "formright'>" >< res[2]
    )
    {
      blob = strstr(res[2], ">Version: </td>");
      if ("</tr>" >< blob) blob = blob - strstr(blob, "</tr>");

      pat = "formright'> *([0-9]+\.[^<]+)<";
      matches = egrep(pattern:pat, string:blob);
      if (matches)
      {
        foreach match (split(matches, keep:FALSE))
        {
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            version = item[1];
            version = ereg_replace(pattern:" +$", replace:"", string:version);
            break;
          }
        }
      }
    }

    installs = add_install(
      appname  : "openadmin_tool",
      installs : installs,
      port     : port,
      dir      : dir,
      ver      : version,
      cpe      : "cpe:/a:ibm:openadmin_tool"
    );

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}
if (isnull(installs))
  exit(0, "OpenAdmin Tool was not detected on the web server on port "+port+".");


# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    display_name : "OpenAdmin Tool"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
