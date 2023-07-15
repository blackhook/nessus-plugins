#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(11652);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"MantisBT Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a bug tracking application written in
PHP.");
  script_set_attribute(attribute:"description", value:
"MantisBT, an open source bug tracking application written in PHP and
using a MySQL back-end, was detected on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mantisbt:mantisbt");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "http_login.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("ssl_funcs.inc");

function login_and_get_version(f_dir, f_port)
{
  local_var f_login_user, f_login_pass, f_login_page, f_login_fields;
  local_var f_check_page, f_version_regex, f_hfl_res, f_res, f_matches, f_version_regex_new;
  local_var f_page, encaps, transport;

  f_login_user    = get_kb_item("http/login");
  f_login_pass    = get_kb_item("http/password");
  if (isnull(f_login_user) || isnull(f_login_pass))
    return NULL;

  # Check that the channel is encrypted
  encaps = get_port_transport(port);
  if (empty_or_null(encaps) || encaps <= ENCAPS_IP)
    exit(0, "Nessus will not attempt login over cleartext channel on port " + port + ". Please enable HTTPS on the remote host to attempt login.");
  transport = ssl_transport(ssl:TRUE, verify:FALSE);

  f_login_page    = "login.php";
  f_login_fields  = "username="+f_login_user+"&password="+f_login_pass+"&return=index.php";
  f_check_page    = "manage_overview_page.php";
  f_version_regex = 'MantisBT Version</td>\\n<td>([0-9.A-Za-z]+)';
  f_version_regex_new = 'MantisBT Version</th>\\n\\t\\t\\t<td>([0-9.A-Za-z]+)';


  if (f_dir == "/") f_page = f_login_page;
  else f_page = f_dir + "/" + f_login_page;

  f_hfl_res = http_form_login(
    port: f_port,
    save_cookies: TRUE,
    method: "POST",
    form: f_page,
    fields: f_login_fields,
    check_page: f_dir + "/" + f_check_page,
    regex: "(Logged in as: <span class=|MantisBT Version)",
    follow_redirect: TRUE,
    re_icase: TRUE
  );

  if (f_hfl_res != 'OK') return NULL;

  # Grab version page
  f_res = http_send_recv3(
    port : f_port,
    item : f_dir + "/manage_overview_page.php",
    method : 'GET',
    transport : transport,
    exit_on_fail : TRUE
  );

  # Look for version
  f_matches = pregmatch(string:f_res[2], pattern:f_version_regex);
  if (isnull(f_matches))
    f_matches = pregmatch(string:f_res[2], pattern:f_version_regex_new);
    
  if (isnull(f_matches))
    return NULL;

  return(f_matches[1]);
}

#
# The script code starts here
#

port = get_http_port(default:80, php:TRUE);
app_name = "MantisBT";

if (thorough_tests) dirs = list_uniq(make_list("/bugs", "/mantis", "/mantisbt", cgi_dirs()));
else dirs = make_list(cgi_dirs());

pages = make_list("/manage_overview_page.php", "/login_page.php");
version_regexes = make_list(
  '>Mantis (\\d[0-9.A-Za-z]+)',
  '>MantisBT (\\d[0-9.A-Za-z]+)',
  'MantisBT Version</td>\\n<td>([0-9.A-Za-z]+)'
);

# For each potential directory, check each potential page
# for version information. If all potential pages for a
# directory fail to provide a version, but the directory
# appears to be Mantis, attempt a login to grab the version.
# If the login version-grab fails, then we have a Mantis
# install for which we cannot get version and need to use
# UNKNOWN_VER and save that.
foreach dir (dirs)
{
  clear_cookiejar();
  install_is_present = FALSE;

  foreach page (pages)
  {
    version = NULL;
    html = get_http_page(port:port, url:dir+page);

    if (
      isnull(html) ||
      (
        html !~ '/images/mantis_logo.png"'
        &&
        html !~ 'Mantis(BT)?'
      )
    ) continue;

    install_is_present = TRUE;

    foreach version_regex (version_regexes)
    {
      matches = pregmatch(string:html, pattern:version_regex, icase:TRUE);
      if (isnull(matches))
        continue;

      version = matches[1];
      break;
    }

    if (isnull(version)) continue;
    register_install(vendor:"MantisBT", product:"MantisBT", app_name:app_name, port:port, path:dir, webapp:TRUE, version:version, cpe: "cpe:/a:mantisbt:mantisbt");
    break;
  }

  if (!isnull(version) || !install_is_present) continue;

  # Attempt login
  version = login_and_get_version(f_dir:dir, f_port:port);
  if (isnull(version)) version = UNKNOWN_VER;
  register_install(vendor:"MantisBT", product:"MantisBT", app_name:app_name, port:port, path:dir, webapp:TRUE, version:version, cpe: "cpe:/a:mantisbt:mantisbt");
}

if (report_installs(port:port, app_name:app_name) == IF_NOT_FOUND)
  audit(AUDIT_WEB_FILES_NOT, app_name, port);
