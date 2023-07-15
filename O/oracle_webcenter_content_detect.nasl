#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57977);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_name(english:"Oracle WebCenter Content Detection");

  script_set_attribute(attribute:"synopsis", value:
"A web-based content management system is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"Oracle WebCenter Content (formerly known as Enterprise Content
Management), a web-based content management system, is running on the
remote host.

Note that for accurate results, you may need to enable the Oracle WebCenter Content port (by default 16200) in your
Nessus scan.");
  # https://www.oracle.com/technetwork/middleware/webcenter/content/overview/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76006e2c");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 16200);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("ssl_funcs.inc");

app_name = "Oracle WebCenter Content";

function parse_version(version)
{
  local_var item, versions;

  versions = make_array();

  # try to parse 11.1.1.8 version
  # 11.1.1.8.0-2013-07-11 17:07:21Z-r106802
  # 11.1.1.8.0PSU-2013-09-13 15:21:10Z-r110081
  item = pregmatch(pattern: "^([0-9.]+)(?:PSU|-dbconfig|)-[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:Zz]+-r([0-9]+)$",
                   string: version);
  if(!empty_or_null(item) && !empty_or_null(item[1]) && !empty_or_null(item[2]))
  {
    versions['main_ver'] = item[1];
    versions['sub_ver'] = item[2];
    return versions;
  }

  # try to parse 10.x version
  # 10.1.3.5.1 (130612)
  item = pregmatch(pattern: "^([0-9.]+)[ ]*\(([0-9]+)\)[ ]*$",
                   string: version);
  if(!empty_or_null(item) && !empty_or_null(item[1]) && !empty_or_null(item[2]))
  {
    versions['main_ver'] = item[1];
    versions['sub_ver'] = item[2];
    return versions;
  }

  # try to parse 11.x version
  # 11gR1-11.1.1.7.0-idcprod1-130304T092605
  item = pregmatch(pattern: "^[^-]+-([0-9.]+)-[^-]+-([0-9T]+)$",
                   string: version);
  if(!empty_or_null(item) && !empty_or_null(item[1]) && !empty_or_null(item[2]))
  {
    versions['main_ver'] = item[1];
    versions['sub_ver'] = item[2];
    return versions;
  }

  return versions;
}

function get_version(dir, port)
{
  local_var res, url, username, password, val, postdata;

  url = dir + "/idcplg?IdcService=GET_ENVIRONMENT&IsJson=1";
  res = http_send_recv3(method:"GET", item:url, port:port, follow_redirect: 2, exit_on_fail:TRUE);
  # No authentication required
  if (
    '"ProductVersion"' >< res[2] &&
    '"ContentManagement"' >< res[2] &&
    '"IdcService"' >< res[2] && '"IsJson"' >< res[2]
  )
  {
    return res;
  }
  # Authentication required
  else if (
    '<div class="idcLargeFormTitle">Login</div>' >< res[2] &&
    'action="j_security_check"' >< res[2] &&
    'input id="j_username"' >< res[2] &&
    'input id="j_password"' >< res[2] &&
    !empty_or_null(get_kb_item("http/login")) &&
    !empty_or_null(get_kb_item("http/password")) &&
    !empty_or_null(encaps) &&
    encaps > ENCAPS_IP
  )
  {
    var transport = ssl_transport(ssl:TRUE, verify:FALSE);

    val = get_http_cookie(name:"JSESSIONID");
    if (empty_or_null(val)) exit(1, "Failed to extract the session cookie from the Oracle WebCenter Content install.");

    postdata =
      "j_username=" + username + "&" +
      "j_password=" + password + "&" +
      "j_character_encoding=UTF-8";

    res = http_send_recv3(
      method:          "POST",
      item:            dir + "/j_security_check",
      port:            port,
      data:            postdata,
      content_type:    "application/x-www-form-urlencoded",
      follow_redirect: 2,
      exit_on_fail:    TRUE,
      transport:       transport
    );

    if (
      '"ProductVersion"' >< res[2] &&
      '"ContentManagement"' >< res[2] &&
      '"IdcService"' >< res[2] # IsJson no longer in reply
      #'"IdcService"' >< res[2] && '"IsJson"' >< res[2]
    )
    {
      return res;
    }
    else
    {
      return NULL;
    }
  }
  else if (
    '<div class="idcLargeFormTitle">Login</div>' >< res[2] &&
    'action="j_security_check"' >< res[2] &&
    'input id="j_username"' >< res[2] &&
    'input id="j_password"' >< res[2] &&
    !empty_or_null(get_kb_item("http/login")) &&
    !empty_or_null(get_kb_item("http/password")) &&
    (empty_or_null(encaps) || encaps <= ENCAPS_IP)
    )
  {
    spad_log(message:"Nessus will not attempt login over cleartext channel on port " + port + ". Please enable HTTPS on the remote host to attempt login.");
    no_https = TRUE;
    return NULL;
  }
  else
  {
    return NULL;
  }
}

clear_cookiejar();
port = get_http_port(default:16200);
encaps = get_port_transport(port);

dirs = make_list("/cs", "/idc", "/");

install_found = FALSE;
no_https = FALSE;

foreach dir (dirs)
{
  res = get_version(dir: dir, port: port);
  if (!empty_or_null(res))
  {
    # "ProductVersion": "11gR1-11.1.1.7.0-idcprod1-130304T092605",
    item = pregmatch(pattern:'"ProductVersion"[ \t]*:[ \t]*"([^"]+)"', string:res[2]);
    if (!empty_or_null(item) && !empty_or_null(item[1]))
      version = item[1];

    versions = parse_version(version: version);

    if(!empty_or_null(versions['main_ver']) && !empty_or_null(versions['sub_ver']))
    {
      version = versions['main_ver'] + " (" + versions['sub_ver'] + ")";
    }
    else
    {
      version = UNKNOWN_VER;
    }

    install_found = TRUE;

    register_install(
      app_name : app_name,
      vendor : 'Oracle',
      product : 'Fusion Middleware',
      path     : dir,
      version  : version,
      port     : port,
      cpe      : "cpe:/a:oracle:fusion_middleware",
      webapp   : TRUE
    );

    if(!thorough_tests) break;
  }
}

if (!install_found && no_https)
  audit(AUDIT_HOST_NOT, 'using HTTPS. Nessus will not attempt login over cleartext channel on port ' + port);
if (!install_found) audit(AUDIT_WEB_APP_NOT_INST, app_name, port);

report_installs(port:port);
