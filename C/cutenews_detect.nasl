#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(17255);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_name(english:"CuteNews Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a news management script written in
PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running CuteNews, a news management script written
in PHP that uses flat files for storage.");
  script_set_attribute(attribute:"see_also", value:"http://cutephp.com/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cutephp:cutenews");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("install_func.inc");


port = get_http_port(default:80, php: 1);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/cutenews", "/news", "/cute", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # If it's CuteNews....
  if (res =~ "Powered by .+CuteNews")
  {
    # Try to identify the version number from index.php.
    ver = NULL;

    pat = "Powered by .+>CuteNews (.+)</a>";
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          ver = item[1];
          break;
        }
      }
    }

    # If unsuccessful, try to grab it from the README.
    if (isnull(ver))
    {
      res = http_send_recv3(
        port   : port,
        method : "GET", exit_on_fail: 1,
        item   : dir+"/README.htm"
      );

      pat = '<p align="left">CuteNews v(.+) by <a';
      matches = egrep(pattern:pat, string:res[2], icase:TRUE);
      if (matches)
      {
        foreach match (split(matches, keep:FALSE))
        {
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            ver = item[1];
            break;
          }
        }
      }
    }

    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/cutenews"),
      value:string(ver, " under ", dir)
    );
    set_kb_item(name:"www/cutenews", value:TRUE);
    if (installs[ver]) installs[ver] += ';' + dir;
    else installs[ver] = dir;

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}


# Report findings.
if (max_index(keys(installs)))
{
  if (report_verbosity)
  {
    info = "";
    n = 0;
    foreach ver (sort(keys(installs)))
    {
      info += '  Version : ' + ver + '\n';
      foreach dir (sort(split(installs[ver], sep:";", keep:FALSE)))
      {
        if (dir == '/') url = dir;
        else url = dir + '/';

        register_install(
          app_name:"CuteNews",
          vendor : 'CutePHP',
          product : 'CuteNews',
          path:url,
          version:ver,
          port:port,
          cpe: "cpe:/a:cutephp:cutenews");

        info += '  URL     : ' + build_url(port:port, qs:url) + '\n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following instance';
    if (n == 1) report += ' of CuteNews was';
    else report += 's of CuteNews were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
