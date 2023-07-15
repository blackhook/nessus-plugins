#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49069);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_xref(name:"IAVT", value:"0001-T-0722");

  script_name(english:"Splunk Management API Detection");
  script_summary(english:"Attempts to access Splunk via REST API.");

  script_set_attribute(attribute:"synopsis", value:
"An infrastructure monitoring tool is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote web server is an instance of the Splunk management API.
Splunk is a search, monitoring, and reporting tool for system
administrators.");
  script_set_attribute(attribute:"see_also", value:"https://www.splunk.com/en_us/software.html");
  script_set_attribute(attribute:"see_also", value:"http://dev.splunk.com/restapi");
  # https://answers.splunk.com/answers/156/what-uses-the-management-port.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3aa0f4e2");
  script_set_attribute(attribute:"see_also", value:"https://www.splunk.com/en_us/download/universal-forwarder.html");
  script_set_attribute(attribute:"solution", value:"
Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:universal_forwarder");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8089);

  exit(0);
}

include("http.inc");
include("install_func.inc");
include("spad_log_func.inc");

port = get_http_port(default:8089, embedded:TRUE);
app = "Splunk";
ver = UNKNOWN_VER;

# checking "Server" HTTP header in banner to determine if we are looking at Splunkd
banner = get_http_banner(port:port);
spad_log(message:'Getting HTTP banner on port ' + port + ': ' + obj_rep(banner));

if (isnull(banner)) audit(AUDIT_WEB_BANNER_NOT,port);

headers = parse_http_headers(status_line:banner, headers:banner);
spad_log(message:'HTTP headers from banner: ' + obj_rep(headers));

if (isnull(headers))
  audit(AUDIT_FN_FAIL,'parse_http_headers');

server = headers['server'];
if (isnull(server))
  audit(AUDIT_WEB_NO_SERVER_HEADER,port);

if ('Splunkd' >!< server)
  audit(AUDIT_WRONG_WEB_SERVER,port,"Splunkd");

# the remote web server is running Splunkd, now grab the version
# in recents versions (observed on v7.3.0+), the version/build can be retrieved from the home page
pattern = 'build="([0-9a-zA-Z]+)"\\s+version="([0-9\\.]+)"';
item = '/';

cache_res = http_get_cache(port:port, item:item, exit_on_fail:TRUE);
spad_log(message:'cached content for ' + item + ': ' + obj_rep(cache_res));

m = pregmatch(string:cache_res, pattern:pattern);
if (!empty_or_null(m))
{
  if (!empty_or_null(m[2]))
  {
    ver = m[2];
    spad_log(message:'version found (in cache): ' + obj_rep(ver));
  }

  if (!empty_or_null(m[1]))
  {
    build = m[1];
    spad_log(message:'build found (in cache): ' + obj_rep(build));
  }
}

if(ver == UNKNOWN_VER && !build)
  audit(AUDIT_WRONG_WEB_SERVER,port,"Splunkd");

url = '/services/server/info';

# nb: the service will restart if webmirror.nasl successfully accesses
#     /services/server/control/restart so we try several times waiting
#     for it to come back up.
for (tries=5; tries>0; tries--)
{
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (!isnull(res)) break;
  sleep(5);
}
if (isnull(res)) audit(AUDIT_RESP_NOT,port,"a HTTP GET request",code:1);

spad_log(message:'Response from ' + url + ': ' + obj_rep(res));

if ( '401 Unauthorized' >< res[0] )
  spad_log(message:'The URL ' + url + ' requires HTTP Basic Authentication to collect more detailed information about splunkd. This can be configured in Nessus.');

if ( '/server/info/server-info' >< res[2] && '<s:key name="version">' >< res[2] )
{
  var line, block_line, server_roles = [], license = FALSE;

  foreach line (split(res[2], keep:FALSE))
  {
    if (isnull(build) && '<s:key name="build">' >< line)
    {
      build = strstr(line, '<s:key name="build">') - '<s:key name="build">';
      build = build - strstr(build, '</s:key>');
      if ('\n' >< build || '"' >< build || !preg(pattern:"^[0-9][^'<>]*$", string:build)) build = "";
    }
    # 6.2.x
    else if ('<s:key name="product_type">enterprise</s:key>' >< line)
    {
      license = "Enterprise";
    }
    else if ('<s:key name="product_type">lite' >< line)
    {
      license = "Light";
    }
    else if (!license && '<s:key name="isFree">' >< line)
    {
      free = strstr(line, '<s:key name="isFree">') - '<s:key name="isFree">';
      free = free - strstr(free, '</s:key>');
      # nb: the KB item name should use "splunk" not "splunkd".
      if (free == 0)
        license = "Enterprise";
      else if (free == 1)
        license = "Free";
    }
    # Detect Splunk Universal Forwarder and other server roles
    else if ('<s:key name="server_roles">' >< line)
    {
      start = stridx(res[2], '<s:key name="server_roles">');
      end = stridx(res[2], '</s:key>', start);

      server_roles_block = substr(res[2], start, end);
      if (isnull(server_roles_block)) continue;

      foreach block_line (split(server_roles_block, sep:'\n'))
      {
        matches = pregmatch(string:block_line, pattern:"<s:item>(.*)</s:item>");
        if (!empty_or_null(matches) && !empty_or_null(matches[1]))
        {
          if (matches[1] == "universal_forwarder")
            app = "Splunk Universal Forwarder";
          server_roles = make_list(server_roles, matches[1]);
        }
      }
    }
    else if (ver == UNKNOWN_VER && '<s:key name="version">' >< line)
    {
      ver = strstr(line, '<s:key name="version">') - '<s:key name="version">';
      ver = ver - strstr(ver, '</s:key>');
      if ('\n' >< ver || '"' >< ver || !preg(pattern:"^[0-9][^'<>]*$", string:ver)) ver = UNKNOWN_VER;
    }

    if (!isnull(build) && ver != UNKNOWN_VER)
      break;
  }
}

# Normalize version to X.Y.Z, ie : 4.1 denotes 4.1.0
if(ver =~ "^[0-9]+\.[0-9]+$")
  ver += ".0";

set_kb_item(name:'Splunk/ManagementAPI/port', value:port);

extranp = make_array("isapi", TRUE,"isweb",FALSE);
extra = make_array("Management API", TRUE);
if (license)
  extra["License"] = license;
if (build)
  extra["Build"] = build;
if (!empty_or_null(server_roles))
  extra["Server Roles"] = server_roles;

register_install(
  app_name : app,
  vendor : 'Splunk',
  product : 'Universal Forwarder',
  port     : port,
  version  : ver,
  path     : "/",
  extra    : extra,
  extra_no_report : extranp,
  webapp   : TRUE,
  cpe   : "cpe:/a:splunk:splunk"
);
report_installs(app_name:app,port:port);
