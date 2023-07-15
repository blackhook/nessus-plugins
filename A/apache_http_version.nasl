#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48204);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_xref(name:"IAVT", value:"0001-T-0530");

  script_name(english:"Apache HTTP Server Version");
  script_summary(english:"Obtains the version of the remote Apache HTTP server.");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the version number of the remote Apache HTTP
server.");
  script_set_attribute(attribute:"description", value:
"The remote host is running the Apache HTTP Server, an open source web
server. It was possible to read the version number from the banner.");
  script_set_attribute(attribute:"see_also", value:"https://httpd.apache.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "apache_http_error_page_detect.nbin");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("install_func.inc");

extra_array = make_array();
version = NULL;

##
# The Apache server banner always exists (unless mod_security is installed
# and configured to disable it). However, the banner can be configured in
# six different ways, each buiilding off the next:
#
# 1. To just say 'Apache' (aka Prod)
# 2. #1 and the major version (aka Major)
# 3. #2 and the minor version (aka Minor)
# 4. #3 and point version (aka Mininmal)
# 5. #4 the operating system (aka OS)
# 6. #5 and the active mods (aka Full)
# 
# Found in the wild:
# Server: Apache
# Server: Apache/2
# Server: Apache/2.2.15
# Server: Apache/2.2.15 (CentOS)
# Server: Apache/2.4.29 (Unix) OpenSSL/1.0.2k-fips PHP/5.6.31 Phusion_Passenger/5.1.2
# Server: Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/4.2mdk) mod_ssl/2.8.7 OpenSSL/0.9.6c
#
# @param banner the banner from get_http_banner, get_backport_banner, or error page
# @return The server line on success and NULL on failure
# @sideaffect sets the extra_array (os and mods) and version variables
##
function parse_banner(banner)
{
  # This could be one huge regex but I've determined that it would be so unwieldly and
  # unreadable that I've elected to go with a longer more manual approach.
  var apache_banner = pregmatch(pattern:'(?:Server: *)?(Apache[^\\r\\n]*)', string:banner);

  if (empty_or_null(apache_banner))
  {
    return NULL;
  }

  # pull out the OS and modules if they exist
  if ("(" >< apache_banner[1])
  {
    var os_and_mods = pregmatch(pattern:'[^\\(]+\\(([^\\)]+)\\)\\s*(.*)$', string:apache_banner[1]);
    if (!empty_or_null(os_and_mods))
    {
      extra_array["os"] = os_and_mods[1];

      if (!empty_or_null(os_and_mods[2]))
      {
        extra_array["modules"] = os_and_mods[2];
      }
    }
  }

  # extract the Apache version if it exists
  version = NULL;
  if ("/" >< apache_banner[1])
  {
    var version_match = pregmatch(pattern:"^[^/]+/([0-9\\.]+)", string:apache_banner[1]);
    if (!empty_or_null(version_match))
    {
      version = version_match[1];
    }
  }
  return apache_banner[0];
}

##
# Checks if the Server header is for Apache
#
# @param banner the banner from get_http_banner or get_backport_banner
#
# @return TRUE if the Server header belongs to Apache
#         FALSE if the Server header doesn't belong to Apache
##
function apache_check_banner(banner)
{
  if (
      "Apache" >!< banner ||
      preg(string:banner, pattern:'Server:.*(Apache[ -]Coyote|Tomcat)', icase:TRUE, multiline:TRUE) ||
      !preg(string:banner, pattern:'Server:.*(Apache[^\\r\\n]*)', icase:TRUE, multiline:TRUE)
  )
    return FALSE;

  return TRUE;
}

# statisfy the prereq
get_kb_item_or_exit("www/apache");

appname = "Apache";
port = get_http_port(default:80);

# Banner in this context is the fingerprint from the server header or error page
banner = NULL;

# Parse the version from error pages
# this is secondary to the server banner and only with paranoid reporting enabled
source = get_kb_item("www/" + port + "/apache/error_page/source");
if (!empty_or_null(source))
{
  banner = get_http_banner(port:port, exit_on_fail:FALSE);
  if (empty_or_null(banner) || !apache_check_banner(banner:banner))
    banner = source; # Use Apache version from error page
}
# Check HTTP banner
else
{
  banner = get_http_banner(port:port, exit_on_fail:TRUE);
  if ("Server:" >!< banner)
    audit(AUDIT_WEB_NO_SERVER_HEADER, port);

  if (!apache_check_banner(banner:banner))
    audit(AUDIT_WRONG_WEB_SERVER, port, appname);
}

# Parse out version, OS, and modules from the banner
apache_banner = parse_banner(banner:banner);

if (empty_or_null(apache_banner))
  audit(AUDIT_WRONG_WEB_SERVER, port, appname);

# Store old style kb items for downstream use
set_kb_item(name:"www/" + port + "/apache", value:TRUE);
set_kb_item(name:"www/apache/" + port + "/pristine/source", value:apache_banner);
extra_array["Source"] = apache_banner;
if (!empty_or_null(version))
{
  set_kb_item(name:"www/apache/" + port + "/pristine/version", value:version);
}

# Parse backported banner
backport_banner = get_backport_banner(banner:banner);
if (backport_banner != banner)
{
  # backport banner returned a new banner so reparse
  version = NULL;
  apache_banner = parse_banner(banner:backport_banner);
}

if (!empty_or_null(apache_banner))
{
  extra_array["backported"] = backported;
  set_kb_item(name:"www/apache/" + port + "/source", value:apache_banner);
  set_kb_item(name:"www/apache/" + port + "/backported", value:backported);
}

if ((!empty_or_null(version)))
{
  set_kb_item(name:"www/apache/" + port + "/version", value:version);
}

register_install(
    vendor:"Apache",
    product:"HTTP Server",
    app_name:appname,
    path:'/',
    version:version,
    port:port,
    extra:extra_array,
    webapp:TRUE,
    cpe: "cpe:/a:apache:http_server");

report_installs(app_name:appname, port:port);
