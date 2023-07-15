#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53574);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/07");

  script_xref(name:"IAVT", value:"0001-T-0762");

  script_name(english:"Atlassian Confluence Wiki Detection");

  script_set_attribute(attribute:"synopsis", value:
"A wiki web application is running on the remote web server.");
  script_set_attribute(attribute:"description", value:
"Atlassian Confluence, a wiki written in Java, is running on the remote
web server.

Note: The plugin supports authentication when HTTP basic or digest
access credentials are supplied in the configuration.");
  script_set_attribute(attribute:"see_also", value:"https://www.atlassian.com/software/confluence");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 443, 8080, 8090, 8443);

  exit(0);
}

include("http.inc");
include("ssl_funcs.inc");
include("spad_log_func.inc");
include("webapp_func.inc");


if (get_kb_item("Settings/disable_cgi_scanning"))
  exit(0, "This plugin only runs if 'Scan web applications' is enabled.");

##
# A wrapper function to handle authenticated web requests
# Used to obtain session token and make subsequent request
# to a reliable resource where version information exists.
#
# @param method is the type of http based request
# @param port the server is listening on
# @param item resource to access
# @param data optional auth payload
# @return the http response
##
function confluence_request(method, port, item, data)
{
  var res = http_send_recv3(
    method          : method,
    port            : port,
    item            : item,
    content_type    : 'application/x-www-form-urlencoded',
    data            : data,
    transport       : transport,
    exit_on_fail    : FALSE,
    follow_redirect : 0
  );

  if (isnull(res)) spad_log(message:'The web server on port '+port+' failed to respond.');

  return strcat(res[1], res[2]);
}

##
# Vars
##
var cpe, port, app_name, extra, path;
cpe = 'cpe:/a:atlassian:confluence';
app_name = 'confluence';

port = get_http_port(default:8090);

extra = make_array();
path = '/';

var user = get_kb_item("http/login");
var pass = get_kb_item("http/password");

var canon_url_pats = [
  '<a.*id="confluence-about-link".*href="[^"]*/aboutconfluencepage\\.action"',
  '<form.*name="loginform" method="POST" action="[^"]*/dologin\\.action"', # 3.x
  '<a.*href="[^"]*/login\\.action">Log In</a>', # 2.x
  '<a.*href="[^"]*/forgotuserpassword\\.action">Forgot password\\?</a>'
];

var ver_pats = [
  'Powered by.*Atlassian Confluence *</a> *(?:<span[^>]+>)?(\\d+\\.[\\w.]+)(?:</span>)?',
  'Powered by.*[\r\n]*.*> *Atlassian Confluence *<.*[\r\n]*.*Version: *(\\d+\\.[\\w.]+) *(?:Build:#? *(\\d+))?',
  '"ajs-version-number" +content="(\\d.+)">',
  '"poweredby".*[\r\n]*.*> *Atlassian Confluence *</a> *(\\d+\\.[\\w.]+)',
  'Powered *by.*>Atlassian Confluence<.*footer-build-information\\\'>(\\d+\\.\\d+\\.\\d+)'
];

var legacy_pat, footer_pat, builds_pat;
legacy_pat = '<a.*href="(?:https?://)?[^/]*(.*)/(login|forgotpassword|aboutconfluencepage)\\.action"';
footer_pat = 'Powered *by.*>Atlassian Confluence<';
builds_pat = 'ajs-build-number" +content="(\\d+)">';

var version = UNKNOWN_VER, build = UNKNOWN_VER;
var detected = FALSE, matches = NULL;
var body = NULL, line = NULL;
var footer_content = NULL;

##
# Perform a credentialed version check
##
if (!empty_or_null(user) && !empty_or_null(pass))
{
  var encaps, secure, transport;
  # Set transport to ssl/tls with verify set to false 
  # to handle self-signed certificates
  transport = ssl_transport(ssl:TRUE, verify:FALSE);
  # Check if transport is secure before sending credentials
  encaps = get_port_transport(port);
  # Confluence server uses secure transport over 443 and 8443
  secure = TRUE;
  # ENCAPS_IP is over TCP without SSL/TLS (insecure)
  if (empty_or_null(encaps) || encaps <= ENCAPS_IP)
  {
    secure = FALSE;
    spad_log(message:'An authenticated request to Confluence has failed because the HTTP transport is insecure.');
  }

  ## auth request
  if (secure)
  {
    var data = strcat('os_username=', user, '&os_password=', pass, '&login=Log+in', '&os_destination=');
    var sess_resp, sess_token, conf_resp, conf_vers, build_resp, build_vers;
    
    # Initialize cookiejar
    init_cookiejar();

    # Get an auth token
    sess_resp = confluence_request(method:'POST', port:port, item:'/dologin.action', data:data);
    
    if (!isnull(sess_resp)) sess_token = pregmatch(string:sess_resp, pattern:"JSESSIONID=(\w+)");
    else spad_log(message:'Could not obtain a valid auth token for this session.');
    
    # check auth token for empty or null value
    if (!empty_or_null(sess_token))
    {
      # Set the path now that we have access token
      path = '/aboutconfluence.action';
      # Set the auth token inside Cookie field
      set_http_cookie(name:'JSESSIONID', value:sess_token[1]);
      
      # Request version information from the aboutconfluence.action resource
      conf_resp = confluence_request(method:'GET', port:port, item:'/aboutconfluence.action');
      if (!isnull(conf_resp)) conf_vers = pregmatch(string:conf_resp, pattern:"<h3>Confluence\s(\d+.\d+.\d+)<\/h3>");
      else spad_log(message:'The version information from the about page is missing or invalid.');

      # Build not in aboutconfluence resource, so get it from login page (needed for consistency).
      build_resp = confluence_request(method:'GET', port:port, item:'/login.action');
      if (!isnull(build_resp)) build_vers = pregmatch(string:build_resp, pattern:builds_pat);
      else spad_log(message:'The build information could not be obtained during authenticated request.');

      # Set the version and build for plugin output
      if (!isnull(conf_vers)) version = conf_vers[1];
      if (!isnull(build_vers)) build = build_vers[1];

      # Set detected to true only when a version has been reported
      if (!isnull(version) && version != 'unknown') detected = TRUE; 
      if (!isnull(build)) extra['Build'] = build;
    }
    else spad_log(message:'The session token is either missing or invalid.');
  }
}

if (thorough_tests) paths = list_uniq(make_list( "/confluence", "/wiki", cgi_dirs()));
else paths = cgi_dirs();

##
# Non-Credentialed version check
##
if (!detected)
{
  foreach path (paths)
  {
    detected = FALSE; 
    # List of paths where version information may exist
    var items = ["/", "/login.action", "/500page.jsp"];
    foreach var item (items)
    {
      matches = NULL; body = NULL; line = NULL;
      item = strcat(path, item);

      if (item == path + "/") body = http_get_cache(item:item, port:port, exit_on_fail:FALSE);
      else body = confluence_request(method:'GET', item:item, port:port);
      
      if (!empty_or_null(body))
      {
        footer_content = preg(string:body, pattern:footer_pat, icase:TRUE, multiline:TRUE);
        if (!footer_content) spad_log(message:"Missing Confluence footer in '" + item + "'.");

        foreach var pat (canon_url_pats)
        {
          line = pgrep(string:body, pattern:pat);
          if (!empty_or_null(line)) break;
        }
      }
      else spad_log(message:"Empty or null response returned from request to '" + item + "'.");

      if (!empty_or_null(line)) matches = pregmatch(string:line, pattern:'action="(?:https?://)?[^/]*(.*)/dologin\\.action"');
      else spad_log(message:"None of the canonical URLs matched in '" + item + "'.");
      
      if (isnull(matches))
      {
        matches = pregmatch(string:line, pattern:legacy_pat);
        spad_log(message:"Failed to parse the path from '" + item + "'.");
      }

      # Ensure the canonical URL matches the directory we're currently checking.
      if (!isnull(matches) && path != matches[1])
      {
        spad_log(message:"The canonical URL did not match the expected base URL in '" + item + "'.");
        continue;
      }
      
      # Get version
      foreach ver_pat (ver_pats)
      {
        if (!empty_or_null(body)) matches = pregmatch(pattern:ver_pat, string:body, icase:FALSE);
        if (isnull(matches)) continue;
        
        # Set the version from unauthenticated request
        version = matches[1];
        
        # Older versions contain the build in the same line, (e.g. Version: 1.2.3 Build:#60)
        if (!empty_or_null(matches[2])) build = matches[2];
        break;
      }

      # Get the build information (if available) and include the number in extra data
      # https://developer.atlassian.com/display/CONFDEV/Confluence+Build+Information
      if (build == UNKNOWN_VER || empty_or_null(build))
      {
        # Reset matches to NULL
        matches = NULL;
        if (!empty_or_null(body)) matches = pregmatch(pattern:builds_pat, string:body, icase:TRUE);
        if (!empty_or_null(matches)) build = matches[1];
        else spad_log(message:"Could not obtain build information from '" + item + "'.");
       
        # Set build information in extra data
        if (!isnull(build)) extra['Build'] = build;
      }

      # No need to inspect other pages if version was found break out of loop
      if (version != UNKNOWN_VER && !empty_or_null(version))
      {
        detected = TRUE;
        break;
      }
    }
    if (!detected) continue;

    # Removing call to set kb item will break customer flatline test cases
    set_kb_item(name:"www/"+port+"/confluence/build/" + path, value:build);
  }
}

if (!detected) audit(AUDIT_WEB_APP_NOT_INST, app_name, port);

register_install(
  app_name  : app_name,
  vendor : 'Atlassian',
  product : 'Confluence',
  port      : port,
  path      : path,
  version   : version,
  extra     : extra,
  webapp    : TRUE,
  cpe       : cpe
);

# Match new local detections' app_name
register_install(
  app_name  : 'Atlassian Confluence',
  vendor : 'Atlassian',
  product : 'Confluence',
  port      : port,
  path      : path,
  version   : version,
  extra     : extra,
  webapp    : TRUE,
  cpe       : cpe
);

report_installs(app_name:app_name, port:port);
