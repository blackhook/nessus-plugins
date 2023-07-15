#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46815);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/07");

  script_name(english:"MySQL Enterprise Monitor (MEM) Web Detection");
  script_summary(english:"Looks for the version of the MySQL Enterprise Monitor.");

  script_set_attribute(attribute:"synopsis", value:
"A web-based database monitoring application was detected on the remote
host.");
  script_set_attribute(attribute:"description", value:
"MySQL Enterprise Monitor (MEM), a distributed application for
monitoring multiple MySQL servers, is hosted on the remote web server.");
  script_set_attribute(attribute:"see_also", value:"https://www.mysql.com/products/enterprise/monitor.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mysql:enterprise_monitor");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 18080, 18443);

  exit(0);
}

include('http.inc');
include('webapp_func.inc');
include('ssl_funcs.inc');
include('spad_log_func.inc');
include('install_func.inc');

app  = 'MySQL Enterprise Monitor';
port = get_http_port(default:18080);

# Version < 3.0.20
dir = '/';
res = http_send_recv3(
  method:'GET',
  item:'/',
  port:port,
  follow_redirect:3,
  exit_on_fail:FALSE
);
spad_log(message:'Initial res for / is : ' + obj_rep(res));

install_registered = FALSE;

if (
  'MySQL Enterprise Dashboard</title>' >< res[2] &&
  '<td align="right">Monitor Instance</td>' >< res[2]
)
{
  spad_log(message:'Found the MySQL Enterprise Dashboard title');
  pattern = '<td id="footerInfo">\\s+([0-9.]+)';
  matches = pregmatch(string:res[2], pattern:pattern, icase:TRUE);

  if (!empty_or_null(matches))
  {
    version = matches[1];
    spad_log(message:'version is: ' + obj_rep(version));
  }
  installs = add_install(
    appname:app,
    installs:installs,
    port:port,
    dir:dir,
    ver:version,
    cpe: 'cpe:/a:mysql:enterprise_monitor'
  );
}

# Version => 3.0.20 
if (max_index(keys(installs)) == 0)
{
  spad_log(message:'Checking for MySQL Enterprise Monitor manual');
  regexes = make_list();
  regexes[0] = make_list("This manual documents the MySQL Enterprise Monitor version");
  regexes[1] = make_list("<title>MySQL Enterprise Monitor ([0-9.]+)(?: Manual)?</title>");

  checks = make_array();
  checks['/Help.action'] = regexes;

  installs = find_install(
    appname : app,
    checks  : checks,
    dirs    : make_list(dir),
    port    : port,
    follow_redirect: 2
  );
}

# Version 3.3.x and 8.x
if (max_index(keys(installs)) == 0)
{
  spad_log(message:'Still no installs');
  if (!isnull(res) &&
      'MySQL Enterprise Monitor' >< res[2]
    )
  {
    spad_log(message:'recent version detected');
    version = UNKNOWN_VER;
    # grab CSRF token from head section
    title_start = stridx(res[2], '<title>');
    top = substr(res[2], 0, title_start);
    pat = '<meta\\s+name="_csrf"\\s+content="([a-zA-Z0-9\\-]+)"';
    match = pregmatch(pattern:pat, string:top);
    if (!isnull(match))
    {
      spad_log(message:'Got _csrf');
      csrf = match[1];
      # log in

      user = get_kb_item('http/login');
      pass = get_kb_item('http/password');
      # Check that the channel is encrypted
      encaps = get_port_transport(port);
      if (empty_or_null(encaps) || encaps <= ENCAPS_IP)
        exit(0, 'Nessus will not attempt login over cleartext channel on port ' + port + '. Please enable HTTPS on the remote host to attempt login.');
      transport = ssl_transport(ssl:TRUE, verify:FALSE);

      postdata = strcat('_csrf=', csrf, '&j_username=', user, '&j_password=', pass);
      res = http_send_recv3(
        method:'POST',
        item:'/j_spring_security_check',
        port:port,
        data:postdata,
        add_headers:make_array('Content-Type', 'application/x-www-form-urlencoded'),
        follow_redirect:1,
        exit_on_fail:FALSE,
        transport:transport
      );

      spad_log(message:'Auth res is: ' + obj_rep(res));

      if (!isnull(res) &&
          '200' >< res[0] &&
          'MySQL Enterprise Monitor' >< res[2] &&
          'Manual</title>' >< res[2]
      )
      {
        spad_log(message:'Got a match after auth');
        # the manual is in the body
        title_end = stridx(res[2], "Manual</title>");
        top = substr(res[2], 0, title_end);
        pat = '<title>MySQL Enterprise Monitor\\s+([0-9\\.]+)\\s+M$';
        match = pregmatch(pattern:pat, string:top);
        if (!isnull(match))
          version = match[1];
      }
    }
    spad_log(message:'Adding the install to installs: ' + obj_rep(installs) + ' and version: ' + obj_rep(version));
    installs = add_install(
      appname:app,
      installs:installs,
      port:port,
      dir:dir,
      ver:version,
      cpe: 'cpe:/a:mysql:enterprise_monitor'
    );
  }
}

spad_log(message:'Installs finally is: ' + obj_rep(installs));

if (max_index(keys(installs)) == 0 ) audit(AUDIT_WEB_APP_NOT_INST, app, port);

report_installs(app_name:app, port:port);

