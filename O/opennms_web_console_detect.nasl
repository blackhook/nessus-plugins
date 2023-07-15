#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(34350);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_name(english:"OpenNMS Web Console Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is used for network management.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running an OpenNMS Web Console. OpenNMS is an
open source, enterprise-grade network management platform, and the Web
Console provides a web-based management interface to it.");
  script_set_attribute(attribute:"see_also", value:"https://www.opennms.org/en");
  script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opennms:opennms");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8980);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:8980);

# Loop through various directories.
dirs = list_uniq(make_list("/opennms", cgi_dirs()));

installs = make_array();
foreach dir (dirs)
{
  # Check whether the login script exists.
  w = http_send_recv3(method:"GET", item:string(dir, "/acegilogin.jsp"), port:port);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # If it does...
  if ('<form action="j_acegi_security_check;jsessionid=' >< res)
  {
    # Save info about it.
    #
    # nb: it doesn't seem possible to get the version remotely.
    ver = "unknown";
    if (dir == "") dir = "/";

    set_kb_item(
      name:string("www/", port, "/opennms"),
      value:string(ver, " under ", dir)
    );
    if (installs[ver]) installs[ver] += ';' + dir;
    else installs[ver] = dir;

    register_install(
      app_name:"OpenNMS Web Console",
      vendor : 'OpenNMS',
      product : 'OpenNMS',
      path:dir,
      version:ver,
      port:port,
      cpe: "cpe:/a:opennms:opennms");

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
        info += '  URL     : ' + build_url(port:port, qs:dir+'/') + '\n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following instance';
    if (n == 1) report += ' of the OpenNMS Web Console was';
    else report += 's of the OpenNMS Web Console were';
    report += ' detected on the\nremote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
