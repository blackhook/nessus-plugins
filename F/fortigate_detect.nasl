#TRUSTED 7c74695566e0bde7fb62903ec86a95fd896cfe833fc19fb1bc28d14e9ddeae1d007d9f599d794817415fdb7b3e984c0af861a210d514978a17c38dfb9f296bce5d9fabab72244d47db40abfd132d739f1daa6ab7f98cde7de5706ea526e651ceeaf870fe87c206e4719180631a77c09d681943b41b5ab9099369599a761ea7a170343b443623d8bed4cfed9b2140b79ff45a8433b636107ccfcd748bf9b6a1cc39fb04dad4bfde444e2007b6aaf2a5d4f4e6983cb90e9150d8e8837bcfe50c8f549a728353ccde47c8bea3da7abaf96d5bf20d0862537a017b40883d24064d7cdd73c81a5827125e2b58df5806c81644f5bd470f0fbc70736681384bd3f8bac8fd16a5866da687dc177730c5021c6350c1f586d6ad43ccc232f2ba808e84fcd179eef2b1943138f7af55ce01783270363fafc040d5c379c62e023e09a9c3b5675cd5cbbca2debacbf1b95a8f5f9a768c14a6ee784437e5bbcf5b6b4a0c9beef56866186565cec46ff7f14a3203eaad6ac655ddee000da15de918e960061d922da31212ade2d54128dd9526c88b4c6c5a298cd4bd93c95cc557da50aef19a5561bc08afa987f5b7cd8a781d0c5018e12648e951cbe66f8611d4c379199f0d0abad3e38464bfb4f2627e848adde01b379b947a57461b5f5d496d29d9f60923729cbd3ca48005f80a0e31b81a475417c1f1ee0d86a8d8e872a43523678851dfe2c6
#TRUST-RSA-SHA256 1b561335cd28548337f554351cad3d977c7f845950cc0c5405bc3a33c0bbea295be071109a76d1e229cbb1959522cccf7b890dbb1633130390da5f7cee4e52b5fd0038ca0de493fcbbe4751f667fb3fd7b7f4002e5a7d99657e4ecafb81b9c441e36a26d2a1f8a78cf984e0908714aecbb1c6b866c5b76c39337a584cd3ba33c2bc1241183152f9dcc343873d51af6b996f856ece1d519fb83dc8746861cd5ea3ee6fe78184805fb12752f51815edbe82fb1357d07840cede4e403eb112afc346f7cfc58afc4a2f09fd141884a1ef86770f241c7ed9df0bb64fa0902929cef28c0ef81a9e44ab6c615478da60c0a5c1f2b0936750b1561c35fdf2af2df902110ec63d37eddf27cc4982df9547c35baae1f3480702c88b58a56c1362187d8ff11067b36686cc59bac6cca49bfa940c4763ee7d26ad45f5054ce42275c51a1ce029b01c1c935b623598611d4241e957eac8792c6f8f351765419f23f49d1443b2ef6ff6ac8ac5bd834e305a2328d9a2939683defcbedb98dc0db687ebac1ea0723a3e57b792cad07fac17e8f9c0bc048421b2c6fa739d250e81f880960ce76f6489cb217ee0ad3d304fc60909d80fe8d4206aed34f3f915070144eeeeef3e5b5e06036015db1caee6d63470f363a55e912564bac9448ca88df1478db3757308e71ae31383647ee3f533ca3874112e4c31fec07452162983fdc6abe854d89aed8b7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17367);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/22");

  script_name(english:"Fortinet FortiGate Web Console Management Detection");
  script_summary(english:"Checks for the Fortinet Fortigate management console.");

  script_set_attribute(attribute:"synopsis", value:
  "A firewall management console is running on the remote host.");
  script_set_attribute(attribute:"description", value:
  "A Fortinet FortiGate Firewall is running on the remote host, and
  connections are allowed to its web-based console management port.

  Letting attackers know that you are using this software will help them
  to focus their attack or will make them change their strategy. In
  addition to this, an attacker may set up a brute-force attack against
  the remote interface.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortinet.com/products/fortigate/");
  script_set_attribute(attribute:"solution", value:
  "Filter incoming traffic to this port.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"hardware_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('http.inc');
include('webapp_func.inc');
include('gunzip.inc');
include('json2.inc');

# replace_kb_item(name:'global_settings/enable_plugin_debugging', value:1);
# replace_kb_item(name:'global_settings/debug_level', value:2);
function serial_to_model(serial)
{
  var s = substr(serial, 0, 5);
  var models = keys(serial_to_model);
  if (contains_element(var:models, value:s));
    return serial_to_model[s];

  return NULL;
}


# https://www.forticloud.com/help/supportedmodels.html
# only populated with models used by our customers in the past two years (as of Dec 2022) as seen in Snowflake
var serial_to_model = {
  'FGT60E': 'FortiGate-60E',
  'FG310B': 'FortiGate-310B',
  'FG800D': 'FortiGate-800D',
  'FG800C': 'FortiGate-800C',
  'FGT61E': 'FortiGate-61E',
  'FG6H1E': 'FortiGate-601E',
  'FGT6HD': 'FortiGate-600D',
  'FG100D': 'FortiGate-100D',
  'FG200F': 'FortiGate-200F',
  'FG201E': 'FortiGate-201E',
  'FG5H1E': 'FortiGate-501E',
  'FOSVM1': 'FortiOS-VM64'
};

var port = get_http_port(default:443, embedded:TRUE);

var app_name = 'FortiOS Web Interface';
var install_found = FALSE;
var version = NULL;
var cpe = 'cpe:/o:fortinet:fortios';
var image_hash, headers, data, extra, s, m, k, d;

# Legacy check first.
var url = '/system/console?version=1.5';
var pattern = 'Fortigate Console Access';

var res = http_send_recv3(
  method:'GET',
  item:url,
  port:port,
  exit_on_fail:FALSE
  );

dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Response of 1st request: ' + obj_rep(res));

if ('200' >< res[0] && preg(string:res[2], pattern:pattern, multiline:TRUE, icase:TRUE))
  install_found = TRUE;

# FortiOS 3.x check next.
if (!install_found)
{
  url = '/images/login_top.gif';
  image_hash = 'f328d4514fe000a673f473e318e862fb';

  res = http_send_recv3(
    method:'GET',
    item:url,
    port:port,
    exit_on_fail:FALSE
    );
  dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Response of 2nd request: ' + obj_rep(res));

  if ('200' >< res[0] && hexstr(MD5(res[2])) == image_hash)
  {
    install_found = TRUE;
    version = '3.0 or earlier';
  }
}

# FortiOS 4.x, 5.x check next.
if (!install_found)
{
  url = '/images/logon_merge.gif';
  image_hash = '3955ddaf1229f63f94f4a20781b3ade4';

  res = http_send_recv3(
    method:'GET',
    item:url,
    port:port,
    exit_on_fail:FALSE
    );
  dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Response of 3rd request: ' + obj_rep(res));

  if ('200' >< res[0] && hexstr(MD5(res[2])) == image_hash)
  {
    install_found = TRUE;
    version = '4.0 or 5.0';
  }
}

# FortiOS 5.x and up
if (!install_found)
{
  url = '/login';
  pattern = '<f-icon class="ftnt-fortinet-grid ';

  res = http_send_recv3(
    method:'GET',
    item:url,
    port:port,
    exit_on_fail:FALSE
  );
  dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Response of 4th request: ' + obj_rep(res));

  if ('200' >< res[0] && preg(string:res[2], pattern:pattern, multiline:TRUE, icase:TRUE))
   {
      install_found = TRUE;
      version = '>= 5.4';
   }
   else
   {
      url = '/431cb5237001e73e794398e4fa3cf660/css/main-green.css';
      pattern = 'fortigate-marketing-';
      headers = {
        'Accept-Encoding': 'gzip, deflate, br'
      };

      res = http_send_recv3(
        method:'GET',
        item:url,
        port:port,
        add_headers:headers,
        exit_on_fail:false
      );

      dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Response of 5th request: ' + obj_rep(res));

      if ('200' >< res[0] && preg(string:gunzip(res[2]), pattern:pattern, multiline:TRUE, icase:TRUE))
      {
        install_found = TRUE;
        version = '>= 6.0';
      }
   }
}

# It's found on some 7.x devices (not verified on < 7.x) that when requesting a non-existent file under the root path
# below response is returned from the device
# curl -k -v https://fortigate.fortidemo.com/robots.txt
# {"status":404,"httpStatus":"error","serial":"FGT2KE3917900165","version":"v7.2.2","build":1255,"api_version":""}
url = '/robots.txt';
res = http_send_recv3(
  method: 'GET',
  item: url,
  port: port,
  fetch404: true,
  exit_on_fail: false
);

dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Response of 6th request: ' + obj_rep(res));

if ('404 Not Found' >< res[0] && 'content-type: application/json' >< tolower(res[1]))
{
  data = json_read(chomp(res[2]));
  d = data[0];
  if (typeof(d) != 'array')
  {
    dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Error occurred while parsing data as JSON: '+obj_rep(d));
  }
  else
  {
    k = keys(d);
    if (
      contains_element(var:k, value:'status') &&
      contains_element(var:k, value:'httpStatus') &&
      contains_element(var:k, value:'serial') &&
      contains_element(var:k, value:'version') &&
      contains_element(var:k, value:'build') &&
      contains_element(var:k, value:'api_version')
    )
    {
      dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Data received: ' + obj_rep(d));
      s = d['serial'];
      m = serial_to_model(serial:s);
      if (m) extra = {'Model': m};
      version = d['version'];
      # remove leading 'v' in 'v7.2.2'
      version = substr(version, 1);
      install_found = true;
    }
  }
}


# Add install to KB and report.
if (install_found)
{
  var installs = add_install(installs:installs, dir:'/', appname:'fortios_ui', ver:version, port:port, cpe:cpe, extra:extra);
  set_kb_item(name:'www/fortios', value:TRUE);
}
else
{
  audit(AUDIT_WEB_APP_NOT_INST, app_name, port);
}

if (report_verbosity > 0)
{
  var report = get_install_report(port:port, installs:installs, item:'/', display_name:app_name);
  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
}
else
{
  security_report_v4(port:port, severity:SECURITY_NOTE);
}
