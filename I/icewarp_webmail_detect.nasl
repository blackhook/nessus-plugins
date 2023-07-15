#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(51097);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/22");

  script_name(english:"IceWarp Webmail Detection");
  script_summary(english:"Checks for IceWarp Webmail");

  script_set_attribute(attribute:"synopsis", value:"The remote web server hosts a webmail application.");
  script_set_attribute(attribute:"description", value:"The remote web server hosts IceWarp, a webmail application.");
  script_set_attribute(attribute:"see_also", value:"https://www.icewarp.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:icewarp:webmail");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 32000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:32000);

# Check if this is the IceWarp web server.
banner = http_server_header(port:port);
if (isnull(banner)) audit(AUDIT_WEB_BANNER_NOT, port);
if ('IceWarp/' >!< banner) audit(AUDIT_WRONG_WEB_SERVER, port, "IceWarp Webmail");

item = eregmatch(pattern:'IceWarp/([0-9\\.]+)', string:banner);
if (isnull(item)) version = NULL;
else version = item[1];

# First try to request /mail for older versions
dir = '/mail';
version = NULL;

res = http_send_recv3(method:"GET", item:dir+'/', port:port, exit_on_fail:TRUE);
if (
  '<TITLE>IceWarp Web Mail</TITLE>' >< res[2] &&
  'Powered by <A HREF="https://www.icewarp.com/"' >< res[2] &&
  'IceWarp Web Mail' >< res[2]
)
{
  # In older versions, the webmail version doesn't match the Server version
  version = NULL;
  pat = 'IceWarp Web Mail ([0-9\\.]+)';
  matches = egrep(pattern:pat, string:res[2]);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        version = item[1];
        break;
      }
    }
  }

  installs = add_install(
    installs:installs,
    ver:version,
    dir:dir,
    appname:'icewarp_webmail',
    port:port,
    cpe: "cpe:/a:icewarp:webmail"
  );
}
else
{
  dir = '/webmail';
  res = http_send_recv3(method:"GET", item:dir+'/', port:port, exit_on_fail:TRUE);
  
  if 
  (
    (
      '<h1>IceWarp Server</h1>' >< res[2] ||
      '<title>IceWarp WebClient</title>' >< res[2]
    ) &&
    (
      'Powered by IceWarp' >< res[2] ||
      'Powered by <a href="http://www.icewarp.com">IceWarp Server' >< res[2]
    )
  )
  {
    # Try to get the version from the webmail page, otherwise fall back to the server banner
    pat = 'Powered by IceWarp <a target="_blank" href="http://www.icewarp.com">Unified Communications</a>[^>]+> Version: ([0-9\\.]+)';

    matches = egrep(pattern:pat, string:res[2]);
    if (!matches)
    {
      pat = 'span title="([0-9\\.]+)">Powered by';
      matches = egrep(pattern:pat, string:res[2]);
    }
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          version = item[1];
          break;
        }
      }
    }
    installs = add_install(
      installs:installs,
      ver:version,
      dir:dir,
      appname:'icewarp_webmail',
      port:port,
      cpe: "cpe:/a:icewarp:webmail"
    );
  }
}

if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, "IceWarp Webmail", port); 

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'IceWarp Webmail',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
