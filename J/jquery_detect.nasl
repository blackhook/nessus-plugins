#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106658);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"JQuery Detection");
  script_summary(english:"Detects JQuery usage");

  script_set_attribute(attribute:"synopsis", value:
"The web server on the remote host uses JQuery.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to detect JQuery on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://jquery.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jquery:jquery");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('install_func.inc');
include('spad_log_func.inc');

function normalize_path(port, url)
{
  url = build_url(port:port, qs:url);
  var fields = split_url(url:url);
  return normalize_url_path(url:fields['page']);
}

appname = 'jquery';

# Examples:
# <script src="/javascript/jquery-1.6.2.js" type="text/javascript"></script>
# <script src="./js/jquery/jquery-1.6.2.js?ts=1348024166" type="text/javascript"></script>
pattern = 'src=["\']([^ ]+jquery-?([0-9\\.]+)?(?:\\.min|\\.slim|\\.slim\\.min)*\\.js[^"]*)["\']';

port = get_http_port(default:80);

res = http_get_cache(item:'/', port:port, exit_on_fail:TRUE);
res = http_normalize_res(res:res);

# Follow redirect if found in cache
if (res[0] =~ '^HTTP/1\\.[01] +30[1237] ')
{
  res = http_send_recv3(method:'GET', port:port, item:'/', follow_redirect:3, exit_on_fail:TRUE);
}

if (empty_or_null(res) || res[0] !~ '^HTTP/[0-9.]+ +200' || empty_or_null(res[2]))
{
  audit(AUDIT_WEB_APP_NOT_INST, 'A valid index page', port);
}

# Parse the JQuery path for each line found.
# Key: path
# Value: version (may be NULL)
paths = {};
errors = 0;

lines = pgrep(string:res[2], pattern:pattern);
foreach line (split(lines))
{
  matches = pregmatch(string:line, pattern:pattern);
  if (empty_or_null(matches))
  {
    spad_log(message:'Line did not match: ' + line);
    errors++;
    continue;
  }

  # If the js src is hosted elsewhere (a http or https URL) and it
  # is not just an absolute link to this host IP then don't continue
  if (matches[1] =~ '^http' && get_host_ip() >!< matches[1])
  {
    spad_log(message:strcat('The remote jquery (', matches[1], ') is not hosted on the target.'));
    errors++;
    continue;
  }

  path = normalize_path(port:port, url:matches[1]);
  if (empty_or_null(path))
  {
    spad_log(message:'Failed to parse the URL: ' + matches[1]);
    errors++;
    continue;
  }

  paths[path] = matches[2];
}

if (empty_or_null(paths))
  audit(AUDIT_WEB_APP_NOT_INST, appname, port);


previous_gzip_option = http_set_gzip_enabled(TRUE);

# Verify that each path is valid an attempt parse the version.
foreach path (keys(paths))
{
  spad_log(message:strcat('Processing ', path, ' on port ', port));

  res = http_send_recv3(method:'GET', port:port, item:path, exit_on_fail:FALSE);
  if (empty_or_null(res) || res[0] !~ '^HTTP/[0-9.]+ +200' || empty_or_null(res[2]))
  {
    spad_log(message:'  Unexpected HTTP response.');
    errors++;
    continue;
  }

  headers = parse_http_headers(headers:res[1]);
  if (headers['content-type'] !~ 'javascript')
  {
    spad_log(message:'  Content-Type is not Javascript.');
    errors++;
    continue;
  }

  # jQuery v2.0.1 / jQuery JavaScript Library v1.9.1
  matches = pregmatch(string:res[2], pattern:'jQuery(?: JavaScript Library)? v([0-9\\.]+)');

  # Prefer the version found in the file over the version found in the filename.
  version = UNKNOWN_VER;
  extra_no_report = {};

  if (!empty_or_null(matches))
  {
    version = matches[1];
    extra_no_report.source = 'File contents';
  }
  else if (!empty_or_null(paths[path]))
  {
    version = paths[path];
    extra_no_report.source = 'File name';
  }

  register_install(
    vendor   : "jQuery",
    product  : "jQuery",
    app_name : appname,
    path     : path,
    version  : version,
    port     : port,
    webapp   : TRUE,
    cpe      : 'cpe:/a:jquery:jquery',
    extra_no_report : extra_no_report
  );
}

http_set_gzip_enabled(previous_gzip_option);

report_extra = NULL;
if (errors > 0)
  report_extra = 'Error(s) occurred during detection. Please enable plugin debugging for more information.';

installs = report_installs(app_name:appname, port:port, extra:report_extra);

if (installs != IF_OK) audit(AUDIT_WEB_APP_NOT_INST, appname, port);
