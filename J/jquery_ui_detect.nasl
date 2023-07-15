#TRUSTED 31598a1d8d20c8d0e54baa84da22e2f696e89fd63258ca1b4ce81ab0ffab317fc2da1519696fd3e4ba5f1e8a89c90a89a258111aa04ee357a8cae6b175751fad7907c435297fccd099b281eacfad0d8e72dd6e1f5d3d1c4a9625e3fd8b7436bf8b76db4dfb3979d0e5da539c24019e177981c6c9a974cbc71d0d253ca4af5117132fdb3eae5358af5060f7fc35e6e9ac8a9d9379b209fcc39337f2dd8f1b354814394057af4000b96af330872c64bae65808add861109bff1306f2ab8ec27ed270f62788842021dcad705f365bfe943674a4a8be76488ecd159bd9f3de588002c08201e68136ea1531b1d758ea52793e7a5ce8b6fcfb63af19dd426a4825d4619ecd75bde92566d898db9cfbc8d1c811fcf0130e2f770cb718c1441aab5574f1fd17fa8d293102627e3d8feb11c6ae7b7d810dcd4da31e3b1f70617c7db2e7db408b23e6c1fd48eb1e376e87d7ce89c21a88dea308c0726a0a9edaafd525433a6d01e79271edd4d035088edd9fb22701695e883785df78f748357fb222fdb9bfd90e729b765d82895c47598bb9d183bb71da5aedf68ae09fc72ac82fda2a10198530ca23d0ad0afd3bd2773183442129bdd21fec3ef2746b14b447746c58aa6334e3972f4ae98c07c3a6f80cc36b96985dee41726a3cebf2492c1e4a7209d8fbfeb7ad6b28fbaa6a9ae33fdbc27a482ed7011cf786fe8262a681fee636ee89fa
#TRUST-RSA-SHA256 2a860ce3237b94b40fa0eefe59e74e22113bfb3f32eca3784ee476c19ad13500cb287850002752d99a5d3062b0c2c71f811d32fb02c876e17c89e4b36e0c298e4b3e86644a1c3e352356c0ab4cf3afcb807706267cb6fef09b3a1f21e11d99bc8268692be175cca82079951f929076c77c00c69e6942cc0a8928a152fd4e59b735694f07e1deef4873f1340814e943a390928d2801d61b58854b06c00b87600a96bb4057390666bbfdbea88edd4b7de51f7e2249fb943701320524b69f48837df6cedccb45d993647ba1eae7fa28d7dad1a45585b8248badb7912e623e28e9b3f3a5ae4c79f833d5207bee3209b293e048d76b8f38663bbcab6728bd58e19254ff73ce713bd05ad16927e91f4e7641228ab2a53f201c85ca6265ff39a3c513e7d9a3c663b2590fdf75980ce83e8aa2b1a66e8d3c5d26c8553485a9b53c635ebed2f8256ca15490f2608f31cee72cc117b4ae62068ea25fa6e67a4984942331964659dc22fc95b708e611581b02770f777151dbc30f675360d2c9272cf29be407be894432a01fa9e2b47a155f4d74746bf83745d17e3d6ced7be80c73fef0376a3f29b68a7b7b69583a8b760925db59e1aba1db51aec12a44f660b52a00625b6453024c326968f6f724c47efda843e5d566d3c7f646951cfd40611d4b1591ddb3a75ecb7d3b71fdfdd82ec6d1e12599523e065b577271de5d70eb0e49288ef4a3
#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(156439);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"jQuery UI Detection");

  script_set_attribute(attribute:"synopsis", value:
"The web server on the remote host uses jQuery UI.");
  script_set_attribute(attribute:"description", value:
"The web server on the remote host uses jQuery UI.");
  script_set_attribute(attribute:"see_also", value:"https://releases.jquery.com/ui/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jquery:jquery_ui");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}


include('http.inc');
include('install_func.inc');
include('spad_log_func.inc');

function normalize_path(port, url)
{
  url = build_url(port:port, qs:url);
  var fields = split_url(url:url);
  return normalize_url_path(url:fields['page']);
}

appname = 'jquery ui';

# Examples:
# <script src="/javascript/jquery-1.6.2.js" type="text/javascript"></script>
# <script src="./js/jquery/jquery-1.6.2.js?ts=1348024166" type="text/javascript"></script>
file_pattern = 'src=["\']([^ ]+jquery-ui(?:\\.min|\\.slim|\\.slim\\.min)*\\.js[^"]*)["\']';

# Examples:
# 1.7.x
# jQuery UI 1.7.x
# 1.7+
# jQuery UI - v1.8.24 - 2012-09-28
ver_pattern = "jQuery UI\s+(?:-\s+)?v?([0-9.]+)";

port = get_http_port(default:443);

res = http_get_cache(item:'/', port:port, exit_on_fail:TRUE);
res = http_normalize_res(res:res);

# Follow redirect if found in cache
if (res[0] =~ '^HTTP/1\\.[01] +30[1237] ')
  res = http_send_recv3(method:'GET', port:port, item:'/', follow_redirect:3, exit_on_fail:TRUE);

if (empty_or_null(res) || res[0] !~ '^HTTP/[0-9.]+ +200' || empty_or_null(res[2]))
  audit(AUDIT_WEB_APP_NOT_INST, 'A valid index page', port);

# Parse the JQuery path for each line found.
# Key: path
# Value: version (may be NULL)
paths = [];
errors = 0;

lines = pgrep(string:res[2], pattern:file_pattern);
foreach line (split(lines))
{
  matches = pregmatch(string:line, pattern:file_pattern);
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
    spad_log(message:strcat('The remote ', appname, ' (', matches[1], ') is not hosted on the target.'));
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

  append_element(var:paths, value:path);
}

if (empty_or_null(paths))
  audit(AUDIT_WEB_APP_NOT_INST, appname, port);


previous_gzip_option = http_set_gzip_enabled(TRUE);

# Verify that each path is valid an attempt parse the version.
foreach path(paths)
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

  matches = pregmatch(string:res[2], pattern:ver_pattern);

  # Prefer the version found in the file over the version found in the filename.
  version = UNKNOWN_VER;

  if (!empty_or_null(matches))
    version = matches[1];

  register_install(
    vendor   : "jQuery",
    product  : "jQuery UI",
    app_name : appname,
    path     : path,
    version  : version,
    port     : port,
    webapp   : TRUE,
    cpe      : 'cpe:/a:jquery:jquery_ui'
  );
}

http_set_gzip_enabled(previous_gzip_option);

report_extra = NULL;
if (errors > 0)
  report_extra = 'Error(s) occurred during detection. Please enable plugin debugging for more information.';

installs = report_installs(app_name:appname, port:port, extra:report_extra);

if (installs != IF_OK) audit(AUDIT_WEB_APP_NOT_INST, appname, port);
