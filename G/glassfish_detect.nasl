#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55930);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_name(english:"Oracle GlassFish HTTP Server Version");
  script_summary(english:"Obtains the version of the remote Oracle GlassFish HTTP Server.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to obtain the version number of the remote Oracle
GlassFish HTTP server.");
  script_set_attribute(attribute:"description", value:
"The remote host is running an Oracle GlassFish HTTP Server, a Java
EE application server. It was possible to read the version number from
the HTTP response headers.");
  # http://www.oracle.com/us/products/middleware/cloud-app-foundation/glassfish-server/overview/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85f4fd5a");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", "Services/unknown", 8080, 8181, 4848, 4949);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("glassfish.inc");
include("install_func.inc");

#
# Main
#

app = 'Oracle GlassFish';

# Possible default ports GlassFish might use.
ports = get_kb_list('Services/www');
if(empty_or_null(ports))
  ports = [];
ports = make_list(ports, 8080, 8181, 4848, 4949);

# We want to search unknown services too because sometimes GlassFish is slow to respond 
# and it could not be detected as HTTP properly (because of timeouts).
if (!get_kb_item("global_settings/disable_service_discovery"))
  ports = make_list(get_unknown_svc_list(), ports);

# For each of the ports we want to try, fork.                         
port = branch(list_uniq(ports));

if (!get_tcp_port_state(port))
  audit(AUDIT_PORT_CLOSED, port, "TCP", code:0);

# Check if this is a GlassFish server.
ssl = false;
res = join(get_glassfish_res(url:'/', ssl:ssl, port:port));

# Try SSL connection if we get empty reponse for HTTP request
if (empty_or_null(res))
{
  res = join(get_glassfish_res(url:'/', ssl:true, port:port));
  ssl = true;
}

# Try SSL connection to identify GlassFish Admin Console in case of redirection
if (('302' >< res) &&
  (preg(pattern:"Location:\s+https://[^/\s]+:" + port, string:res, multiline:TRUE)))
{
  res = join(get_glassfish_res(url:'/', ssl:true, port:port));
  ssl = true;
}

# If GlassFish Admin Console is loading. Grab GlassFish version from another source 
if (('202' >< res) && ('GlassFish Server Administration Console' >< res) && ('Server:' >!< res))
  res = join(get_glassfish_res(url:'/testifbackendisready.html', ssl:ssl, port:port));

if (!res || !preg(string:res, pattern:"(GlassFish|Sun Java System Application Server|Sun-Java-System/Application-Server)", multiline:TRUE, icase:TRUE))
  audit(AUDIT_NOT_DETECT, app);

# Extract Server header from HTTP response headers.
pat = "(((?:Oracle )?GlassFish(?: Enterprise)?|Sun Java System Application Server|Sun-Java-System/Application-Server)[ a-zA-Z]*v?(([.0-9]*)( Patch|_)?\s?([0-9]*)))";
matches = egrep(string:res, pattern:pat, icase:TRUE);

if (matches)
{
  # Parse version number from Server header.
  foreach match (split(matches, keep:FALSE))
  {
    fields = pregmatch(string:match, pattern:pat, icase:TRUE);
    if (!isnull(fields))
    {
      # Extract the server header's data.
      source = fields[1];

      # Set app name according to header
      app = fields[2];

      # Save the original format of the version number.
      if (!isnull(fields[3]))
        pristine = fields[3];

      # Incorporate the patchlevel, if existing, into the version number.
      if (!isnull(fields[4]))
        version = fields[4];

      if (!isnull(fields[5]) && !isnull(fields[6]))
        version += "." + fields[6];

      register_install(
        app_name : app,
        vendor : 'Oracle',
        product : 'GlassFish Server',
        version  : version,
        path     : '/',
        webapp   : TRUE,
        port     : port,
        cpe      : "cpe:/a:oracle:glassfish_server");

      break;
    }
  }
}

set_kb_item(name:"www/glassfish", value:TRUE);
set_kb_item(name:"www/" + port + "/glassfish", value:TRUE);
if (ssl)
  set_kb_item(name:"www/" + port + "/glassfish/ssl", value:TRUE);

if (!isnull(version))
{
  set_kb_item(name:"www/" + port + "/glassfish/source", value:source);
  set_kb_item(name:"www/" + port + "/glassfish/version", value:version);
  set_kb_item(name:"www/" + port + "/glassfish/version/pristine", value:chomp(pristine));
}

if (report_verbosity > 0)
{
  report = '\n' + app;
  if (!isnull(version)) report += ' version '+version;
  report += ' is running on port ' + port + '.\n';
}

report_installs(app_name:app, port:port);
