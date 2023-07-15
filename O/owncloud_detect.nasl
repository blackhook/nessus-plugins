#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(59727);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"ownCloud Web Interface Detection");

  script_set_attribute(attribute:"synopsis", value:
"A web-based cloud storage software suite is running on the remote
host.");
  script_set_attribute(attribute:"description", value:
"ownCloud, a web-based PHP cloud storage software suite, is running on
the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://owncloud.org/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:owncloud:owncloud");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

appname = "ownCloud";
port = get_http_port(default:80, php:TRUE);

dirs = list_uniq(make_list("/owncloud", "/ownCloud", cgi_dirs()));
dirs = list_uniq(dirs);

installs = NULL;

foreach dir (dirs)
{
  ver = UNKNOWN_VER;
  detected = FALSE;
  host = get_host_name();

  # Detect "Untrusted Domain" errors
  # We need to request by IP instead of FQDN
  # if we encounter this error or we won't detect
  # the version.
  url = dir + '/index.php';
  res = http_send_recv3(method:"GET", item:url, host:host, port:port, exit_on_fail:TRUE);

  if("from an untrusted domain" >< res[2]) host = get_host_ip();

  # Detect versions < 6.0
  # In earlier releases we can detect ownCloud on the login
  # page directly.
  url = dir + '/index.php';
  res = http_send_recv3(method:"GET", item:url, host:host, port:port, exit_on_fail:TRUE);

  if("<title>ownCloud</title>" >< res[2] &&
     ">Username<" >< res[2] && ">Password<" >< res[2]) detected = TRUE;

  # Detect versions > 6.0
  # In later versions ownCloud returns the login page for
  # any resource requested, so we have to cause a 404-like error
  # to determine the install dir.
  url = dir + '/Nessus404/index.php';
  res = http_send_recv3(method:"GET", item:url, host:host, port:port, exit_on_fail:TRUE, fetch404:TRUE);

  if(
     "404 Not Found" >< res[0] &&
     res[2] =~ "(Cloud|File) not found<" &&
     "ownCloud</a> – web services under" >< res[2]
    ) detected = TRUE;

  if(detected)
  {

    # Try to obtain version
    res = http_send_recv3(
            method:'GET',
            item:dir+'/status.php',
            host:host,
            port:port,
            exit_on_fail:TRUE
          );

    item = pregmatch(pattern:'"version":"([0-9\\.]+)"', string:res[2]);
    if(!isnull(item[1]))
    {
      ver = item[1];
      installs = add_install(
        installs:installs,
        dir:dir,
        ver:ver,
        appname:'owncloud',
        port:port,
        cpe: "cpe:/a:owncloud:owncloud"
      );

      if (!thorough_tests) break;
    }
  }
}

if (isnull(installs))
  audit(AUDIT_NOT_DETECT, appname, port);

if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    item         : '/index.php',
    display_name : appname
  );
  security_note(port:port, extra:report);
}
else security_note(port);

exit(0);
