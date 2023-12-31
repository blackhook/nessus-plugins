#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67175);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"Atlassian Crowd Detection");

  script_set_attribute(attribute:"synopsis", value:
"An identity tool is running on the remote web server.");
  script_set_attribute(attribute:"description", value:
"Atlassian Crowd, a web-based single sign-on user identity tool written
in Java, is running on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.atlassian.com/software/crowd");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:crowd");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8095);

  exit(0); 
}

include('webapp_func.inc');
port = get_http_port(default:8095);

if (thorough_tests) dirs = list_uniq(make_list("/crowd", cgi_dirs()));
else dirs = make_list(cgi_dirs());

checks = make_array();
regexes = make_list();
regexes[0] = make_list('crowd/console/', 'atlassian', 'Version');
regexes[1] = make_list("Version:&nbsp;([0-9.]+($|[^0-9\s]+([0-9])?))", "Version  ([0-9.]+($|[^0-9\s]+([0-9])?))");
checks["/"] = regexes;

installs = find_install(
  appname : "crowd",
  checks  : checks,
  dirs    : dirs,
  port    : port,
  follow_redirect: 5
);

# Check for older versions
if (empty_or_null(installs))
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('class="crowdForm"');
  regexes[1] = make_list("Version:&nbsp;([0-9.]+($|[^0-9\s]+([0-9])?))", "Version  ([0-9.]+($|[^0-9\s]+([0-9])?))");
  checks["/console/login.action"] = regexes;

  installs = find_install(
    appname : "crowd",
    checks  : checks,
    dirs    : dirs,
    port    : port,
    follow_redirect: 5
  );
}

if (empty_or_null(installs))
  audit(AUDIT_WEB_APP_NOT_INST, "Atlassian Crowd", port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : "Atlassian Crowd",
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
