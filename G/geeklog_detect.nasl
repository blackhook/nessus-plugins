#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36143);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_name(english:"Geeklog Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a content management system written in
PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Geeklog, an open source blog engine /
content management system written in PHP.");
  script_set_attribute(attribute:"see_also", value:"https://www.geeklog.net/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:geeklog:geeklog");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");


port = get_http_port(default:80, embedded: 0, php: 1);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/geeklog", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # If it's Geeklog...
  if (
    '/backend/geeklog.rss" title="RSS Feed:' >< res ||
    '/webservices/atom/?introspection" title="Webservices">' >< res ||
    'Powered by <a href="https://www.geeklog.net/">Geeklog</a>&nbsp;<br>Created' >< res
  )
  {
    version = NULL;

    # Try to grab the version from the changelog.
    url = string(dir, "/docs/changes.html");
    res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: 1);

    if (
      "Geeklog Documentation - Changes</title>" >< res[2] &&
      '<h2><a name="changes' >< res[2]
    )
    {
      foreach line (split(res[2], keep:FALSE))
      {
        if ('<h2><a name="changes' >< line && ">Geeklog " >< line)
        {
          version = strstr(line, "Geeklog ") - "Geeklog ";
          version = version - strstr(version, '</a>');
          break;
        }
      }
    }

    # If still unknown, just mark it as "unknown".
    if (isnull(version)) version = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/geeklog"),
      value:string(version, " under ", dir)
    );
    set_kb_item(name:"www/geeklog", value:TRUE);
    if (installs[version]) installs[version] += ';' + dir;
    else installs[version] = dir;

    register_install(
      app_name:"Geeklog",
      vendor : 'Geeklog',
      product : 'Geeklog',
      path:dir,
      version:version,
      port:port,
      cpe:"cpe:/a:geeklog:geeklog");

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}


# Report findings.
if (max_index(keys(installs)))
{
  if (report_verbosity > 0)
  {
    info = "";
    n = 0;
    foreach version (sort(keys(installs)))
    {
      info += '  Version : ' + version + '\n';
      foreach dir (sort(split(installs[version], sep:";", keep:FALSE)))
      {
        if (dir == '/') url = dir;
        else url = dir + '/';

        info += '  URL     : ' + build_url(port:port, qs:url) + '\n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following instance';
    if (n == 1) report += ' of Geeklog was';
    else report += 's of Geeklog were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
