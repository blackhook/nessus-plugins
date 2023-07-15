#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description) {
  script_id(19496);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"SugarCRM Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CRM system written in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running SugarCRM, a customer relationship
management (CRM) application written in PHP.");
  script_set_attribute(attribute:"see_also", value:"https://www.sugarcrm.com/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sugarcrm:sugarcrm");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Search for SugarCRM
if (thorough_tests) dirs = list_uniq(make_list("/sugarcrm", "/sugar", "/SugarCRM", "/sugarsuite", "/crm", cgi_dirs()));
else dirs = make_list(cgi_dirs());

login_page = '/index.php?action=Login&module=Users';
installs = 0;
n = 0;
installations = make_array();
foreach dir (dirs) {
  # Grab index.php.
  res = http_send_recv3(port:port, method:"GET", item:dir+login_page);
  if (isnull(res)) exit(0);

  # If it looks like SugarCRM...
  if (
    "<!--SugarCRM - Commercial Open Source CRM-->" >< res[2] ||
    "alt='Powered By SugarCRM'>" >< res[2]
  ) {
    # Try to grab the version number from README.txt - Sugar only
    # displays it normally to logged-in users.
    url = string(dir, "/README.txt");
    res = http_send_recv3(method:"GET", item:url, port:port);
    if (isnull(res)) exit(0);

    pat = "^Sugar Suite v([0-9].+)$";
    matches = egrep(pattern:pat, string:res[2]);
    if (matches) {
      foreach match (split(matches, keep:FALSE)) {
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          break;
        }
      }
    }

    # Oh well, just mark it as "unknown".
    if (isnull(ver)) ver = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/sugarcrm"),
      value:string(ver, " under ", dir)
    );
    set_kb_item(name:"www/sugarcrm", value: TRUE);

    if (installations[ver]) installations[ver] += ';' + dir;
    else installations[ver] = dir;
    ++installs;

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}


# Report any instances found unless Report verbosity is "Quiet".
if (installs && report_verbosity > 0) {
  info = "";

  foreach version (sort(keys(installations)))
  {
    info += '\n  Version : ' + version + '\n';

    foreach dir (sort(split(installations[version], sep:";", keep:FALSE)))
    {
      if (dir == '/') url = login_page;
      else url = dir + login_page;

      register_install(
        vendor:"SugarCRM",
        product:"SugarCRM",
        app_name:"SugarCRM",
        path:url,
        version:version,
        port:port,
        cpe: "cpe:/a:sugarcrm:sugarcrm");

      info += '  URL     : ' + build_url(port:port, qs:url) + '\n';
      n++;
    }
  }

  report = '\nThe following instance';
  if (installs == 1) report += ' of SugarCRM was';
  else report += 's of SugarCRM were';
  report += ' detected on the remote host :\n' + info;

  security_note(port:port, extra:info);
}
