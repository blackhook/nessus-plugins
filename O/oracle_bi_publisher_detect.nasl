#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53258);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");
  script_xref(name:"IAVT", value:"0001-T-0683");

  script_name(english:"Oracle BI Publisher Enterprise Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a report publishing application.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts Oracle BI Publisher Enterprise, a report
publishing system written in Java.");
  # https://www.oracle.com/technetwork/middleware/bi-publisher/overview/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8912f2b7");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence_publisher");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 9502, 9704, 8888, 7001);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("url_func.inc");

appname = 'Oracle BI Publisher';
port = get_http_port(default:9704);

ver_pat  = '<meta name=\"Generator\" content=\"Oracle BI Publisher ([0-9.]+) \\((build# [0-9.()]+)';

dirs = make_list('/xmlpserver', cgi_dirs());

if (thorough_tests)
  dirs = make_list(dirs, '/');

dirs = list_uniq(dirs);

installs = 0;
foreach dir (dirs)
{
  res = http_send_recv3(method:"GET", item:dir + '/', port:port);
  if (empty_or_null(res)) continue;

  ver = UNKNOWN_VER;
  detected = false;

  extra = {};
  extra_no_report = {};

  if (
    '<title>Oracle BI Publisher Enterprise Login</title>' >< res[2] &&
    '<meta name="Generator" content="Oracle BI Publisher' >< res[2]
  )
  {
    detected = true;

    matches = pregmatch(pattern:ver_pat, string:res[2], icase:TRUE);
    if (!isnull(matches))
    {
      ver   = matches[1];

      build = str_replace(string:matches[2], find:"#", replace:"");
      build = build - 'build ';
      extra['Build'] = build;
    }
  }
  # Check if redirected to BI Lightweight SSO login page
  else if (
    res[0] =~ "^HTTP/[0-9.]+ +302" &&
    preg(string:res[1], pattern:"Location: .*/bi-security-login/login\.jsp", icase:TRUE, multiline:TRUE)
  )
  {
    res = http_send_recv3(method:"GET", item:dir + '/resources/en/publisher.js', port:port);
    if (empty_or_null(res)) continue;
    
    if ( 
      res[0] =~ "^HTTP/[0-9.]+ +200" &&
      'PublisherPrefs:"Oracle BI Publisher"' >< res[2] &&
      'Publisher:"Oracle BI Publisher' >< res[2]
    )
    {
      detected = true;
      extra_no_report["Lightweight SSO"] = TRUE;
      report = 'Oracle BI Lightweight SSO was detected therefore version detection is not possible remotely at this time.';   
    }
  }

  if (!detected) continue;

  register_install(
    app_name:appname,
    vendor : 'Oracle',
    product : 'Business Intelligence Publisher',
    path:dir,
    port:port,
    version:ver,
    extra:extra,
    extra_no_report:extra_no_report,
    cpe:"cpe:/a:oracle:business_intelligence_publisher",
    webapp:TRUE
  );

  installs++;
  if (!thorough_tests) break;
}

if (installs == 0) audit(AUDIT_WEB_APP_NOT_INST, appname, port);

report_installs(app_name:appname, port:port, extra:report);
