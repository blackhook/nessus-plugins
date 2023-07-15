#TRUSTED 17ac3dcc93ec606a48b26d88070eda1dc74d6752d961cef5882c900def82440e9f744c7ba0270820dfb1cb8d3741fee0684d10a1359a9e49635dd41e597ce76613f74175cfb889f7cf462199a7bc6a007ec297819ccabd7aebffb695927bb6222af4c3b11ce221952012117f9c9ab75c99771e7bdcacc6030e4a732c2bb9a5b63ceafdda79671577fd8b91804c10ef6a3c1a3f28448b3eaee69bafa8c10f3b8c03d75ea26886f7419cde2a91c5883320acfed0a68417f60a7a9bd971b939b73a79d07fc37d356ffcc953a0d8a956a923001c0649d815e12a737296fcf6e9487cccb9d9623859cb795cc1351dd9b1c242276389666a4acd01cc9f8a2ea9e3eb8bd64f54df55072814f4a7c7cd49bc73317259a51c3b67b6c483c9b973ee59eb7862fd7497b5b86bf8651305daf0c628c383e11523d5c3a60865d5fb929b60873fa3f3aee87b997d93ebf0975849873f95315960d27fe94d56cfe5fa0050c494794e2bb2c806bef10795eef188995b3f812048d8b2a82f87fee23e9878ae212b877be5d587cc7d8ce917487bb814591943ca8ffeb46a097dac0e005cb6541f98ff1aa2eaf14007cdcdccbdb734751f4b4f7c4aa2ba7f25c149a328cd63ede059cdf66922145c70b550bd8a3f2470125e5a268ca7860d39a644d30e758f1c82004c9e80c1628747a8d97e37f99b829ef34e8f104766ac924f1b761a0a5480d3b674
#TRUST-RSA-SHA256 9ccb58a18694d5e7a89c1fe968127eaed1abae8fd797a7c12eaf1575c22f557665325435f7d453be0f9fe978ee4968b68d71b2164f5382d655d98db76d64e422b129df7e1e332b885445cc21913bba507fc7c28e96974debe3cdaf4361e658b545bc76f6c8160bc39046a5b12729afe311d8a1738974c65e518141048d43d2cf42dabcad8d8ebc54a8ce1efc217da2ed2af8a26ca5040b23c10db544b80b661486272506d9b50926b1de15ef366104213227021658eebe4ff4bf6a7155852dbc90f4b517a0e54421af7e5e544a40a7eb07bb99925d809c41b8eecaafaaa225eca488542f0733907daa488bca281adebb487e78918d9542ac4b3046acb6728d3784ec0816e567d4e1b79733f0b544171fb312c8eb3f0879bd4e7d0bbbecab5b8e5d2c18903ec107ed23af99de0d64289ae562d9830652498f103669837c07a7af17b0aea91862cb1a7c57edefe63f134af46c4fadc14de863034cab6765307822e5d3d0a5c26cc99367ae3406e73a996f652724881433fe91a3a20acea31c4daa580d56682fd72d4262914dc7d7306175ccf1ee55c2dc882f72dc36797015cab8907c63c1eebd3bb501c517c7c146554892948c358f84c40ee9b8480008bf532463eb04c1269336aef68008ddcd3e5b23494c19dd34f85f2f4d0b089da1f85dbffec42bb5ca5a0147f943ae655f79ece96f32023c9ac4145cf5cc61f1de2665e9

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47619);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_xref(name:"IAVT", value:"0001-T-0723");

  script_name(english:"Splunk Web Detection");
  script_set_attribute(attribute:"synopsis", value:
"An infrastructure monitoring tool is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"The web interface for Splunk is running on the remote host. Splunk is
a search, monitoring, and reporting tool for system administrators.

Note that HTTP Basic Authentication credentials may be required to retrieve version information
for some recent Splunk releases.");
  script_set_attribute(attribute:"see_also", value:"https://www.splunk.com/en_us/software.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("splunkd_detect.nasl");
  script_require_ports("Services/www", 8000);

  exit(0);
}

include("http.inc");
include("install_func.inc");
include("spad_log_func.inc");

var app = "Splunk";
var port = get_http_port(default:8000, embedded:TRUE);
var dir = '/';
var build = FALSE;
var version = UNKNOWN_VER;
var license = FALSE;
var tries, res;

# nb: the service will restart if webmirror.nasl successfully accesses
#     /services/server/control/restart so we try several times waiting
#     for it to come back up.
for (tries=5; tries>0; tries--)
{
  res = http_send_recv3(
    method         : 'GET',
    item           : dir,
    port           : port,
    add_headers    : make_array("User-Agent", "Nessus"),
    follow_redirect: 2
  );
  if (!isnull(res)) break;
  sleep(5);
}

  dbg::detailed_log(
  lvl:1,
  src:SCRIPT_NAME,
  msg:'\n\nHTTP Response ' +
      '\n\nResponse Code: ' + res[0] +
      '\n\nHeaders: ' + res[1] +
      '\n\nBody: ' + res[2] + '\n\n');

if (isnull(res)) audit(AUDIT_RESP_NOT,port,"a HTTP GET request",code:1);

if (
  ('<b>Login to Splunk</b>' >< res[2] && '<h2><b>Welcome to Splunk</b></h2' >< res[2]) ||
  (
    '<meta name="author" content="Splunk Inc."'   >< res[2] &&
    "Splunk.util.normalizeBoolean('"        >< res[2] &&
     pgrep(pattern:"Login *-", string:res[2]) &&
     pgrep(pattern:'<p class="footer">&copy; [0-9-]+ Splunk Inc. Splunk', string:res[2])
  ) ||
  # 3.x
  (
    '<title>Splunk' >< res[2] && 'layerid="splunksMenu"' >< res[2] &&
    'href="http://www.splunk.com">Splunk Inc' >< res[2]
  ) ||
  # 4.0.x
  (
    '<meta name="author" content="Splunk Inc."'   >< res[2] &&
    pgrep(pattern:'<p class="footer">&copy; [0-9-]+ Splunk Inc. Splunk', string:res[2]) &&
    'class="splButton-primary"' >< res[2]
  ) ||
  # 6.2.x-8.x
  (
    '<meta name="author" content="Splunk Inc."' >< res[2] &&
    '<script type="text/json" id="splunkd-partials">' >< res[2]
  )
)
{
  if ('"licenseType": ' >< res[2] || '"license_labels":' >< res[2] || '"product_type":' >< res[2])
  {
    if ('"licenseType": "free"' >< res[2])
      license = "Free";
    else if ('"license_labels":["Splunk Free' >< res[2])
      license = "Free";
    else if ('"licenseType": "pro"' >< res[2])
      license = "Enterprise";
    else if ('"license_labels":["Splunk Enterprise' >< res[2])
      license = "Enterprise";
    else if ('"product_type":"enterprise"' >< res[2])
      license = "Enterprise";
    else if ('"license_labels":["Splunk Light' >< res[2])
      license = "Light";
    else if ('"product_type":"lite' >< res[2])
      license = "Light";
    else if ('"license_labels":["Splunk Forwarder' >< res[2])
      license = "Forwarder";
  }

  # Check if we can get the version...
  var regex = "Login *- *Splunk ([0-9.]+) *(\(([0-9]+)\))?</title>";
  var line = pgrep(pattern:regex,string:res[2]);
  if (line)
  {
    var matches = pregmatch(pattern:regex,string:line);
    if (matches)
    {
      version = matches[1];
      if (matches[3]) build = matches[3];
    }
  }

  if (version == UNKNOWN_VER)
  {
    regex = ">&copy; [0-9-]+ Splunk Inc. Splunk ([0-9.]+) *(build ([0-9]+).)?</p>";
    line = pgrep(pattern:regex,string:res[2]);
    if (line)
    {
      matches = pregmatch(pattern:regex,string:line);
      if (matches)
      {
        version = matches[1];
        if (matches[3]) build = matches[3];
      }
    }
  }

  if (version == UNKNOWN_VER)
  {
    regex = '<div id="footer" versionNumber="([0-9.]+)" *(buildNumber="([0-9]+)")? *installType="prod"';
    line = pgrep(pattern:regex,string:res[2]);
    if (line)
    {
      matches = pregmatch(pattern:regex, string:line);
      if (matches)
      {
        version = matches[1];
        if (matches[3]) build = matches[3];
      }
    }
  }

  if (version == UNKNOWN_VER)
  {
    regex = '"build":"?([a-f0-9]+)"?,.*,"version":"([0-9.]+)"';
    line = pgrep(pattern:regex,string:res[2]);
    if (line)
    {
      matches = pregmatch(pattern:regex, string:line);
      if (matches)
      {
        version = matches[2];
        if (matches[1]) build = matches[1];
      }
    }
  }

  # >6.6.x
  if (version == UNKNOWN_VER)
  {
    regex = '"version":"([0-9.]+)"';
    line = pgrep(pattern:regex,string:res[2]);
    if (line)
    {
      matches = pregmatch(pattern:regex, string:line);
      if (matches)
      {
        version = matches[1];
      }
    }
  }

  # 8.x version can be pulled from /en-US/help
  if (version == UNKNOWN_VER)
  {
    res = http_send_recv3(
      port:port,
      method:'GET',
      item:'/en-US/help',
      follow_redirect: 0,
      exit_on_fail:FALSE
    );

    dbg::detailed_log(
    lvl:1,
    src:SCRIPT_NAME,
    msg:'\n\n8.x version can be pulled from /en-US/help' +
        '\n\nResponse Code: ' + res[0] +
        '\n\nHeaders: ' + res[1] +
        '\n\nBody: ' + res[2] + '\n\n');

    matches = pregmatch(string:res[2], pattern:'var args.*?versionNumber": "(\\d+\\.\\d+\\.\\d+).*?product": "([^"]+)"');
    if (!empty_or_null(matches))
    {
      version = matches[1];
      if(!license) license = matches[2];
    }
  }

  # Attempt to authenticate if version is still not found
  if (version == UNKNOWN_VER)
  {
    # try login to get the version
    var username = get_kb_item("http/login");
    var password = get_kb_item("http/password");

    if (!empty_or_null(username) && !empty_or_null(password))
    {

      init_cookiejar();
      res = http_send_recv3(
        port:port,
        method:'GET',
        item:'/',
        follow_redirect:2,
        exit_on_fail:FALSE
      );

      dbg::detailed_log(
      lvl:1,
      src:SCRIPT_NAME,
      msg:'\n\nProduct version not found on the home page "/". Now trying to retrieve it on a page after user authentication.' +
          '\n\nResponse Code: ' + res[0] +
          '\n\nHeaders: ' + res[1] +
          '\n\nBody: ' + res[2] + '\n\n');

      if (res[0] =~ '^HTTP/[0-9.]+ +200')
      {
        var pattern = "Set-Cookie:\s+cval=(\d+)";
        var match = pregmatch(pattern:pattern, string:res[1]);
        if (!empty_or_null(match) && !empty_or_null(match[1]))
        {
          var cval = match[1];
          var data = 'cval=' + cval + '&username=' + username + '&password=' + password + '&return_to=/en-GB/&set_has_logged_in=false';
          res = http_send_recv3(
            port:port,
            method:'POST',
            item:'/en-GB/account/login',
            data:data,
            exit_on_fail:FALSE
            );

          dbg::detailed_log(
          lvl:1,
          src:SCRIPT_NAME,
          msg:'\n\nNow performing user authentication ({"status": 0} indicates a success):' +
              '\n\nResponse Code: ' + res[0] +
              '\n\nHeaders: ' + res[1] +
              '\n\nBody: ' + res[2] + '\n\n');

          if (res[0] =~ '^HTTP/[0-9.]+ +200')
          {
            res = http_send_recv3(
              port:port,
              method:'GET',
              item:'/en-US/app/launcher/home',
              follow_redirect:3,
              exit_on_fail:FALSE
              );

            dbg::detailed_log(
            lvl:1,
            src:SCRIPT_NAME,
            msg:'\n\nUser has successfully autheticated, try to retrieve the product version from response:' +
                '\n\nResponse Code: ' + res[0] +
                '\n\nHeaders: ' + res[1] +
                '\n\nBody: ' + res[2] + '\n\n');

            pattern = '"version":[ ]+"((?:\\d\\.)+\\d)"';
            match = pregmatch(pattern:pattern, string:res[2]);
            if (!empty_or_null(match) && !empty_or_null(match[1]))
            {
              version = match[1];
              dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:'Product version ' + version + ' found (after user authentication).');
            }
          }
        }
      }
    }
  }

  # Check if the version was found in the Management API
  if (version == UNKNOWN_VER)
  {
    var api_install = get_single_install(app_name:"Splunk", port:get_kb_item('Splunk/ManagementAPI/port'), webapp:TRUE);
    if(!empty_or_null(api_install))
      version = api_install['version'];
  }

  if (version !~ "^[0-9.]+$")
    version = UNKNOWN_VER;

  # Normalize version to X.Y.Z, ie : 4.1 denotes 4.1.0
  if(version =~ "^[0-9]+\.[0-9]+$")
    version += ".0";

  var extranp = make_array("isapi", FALSE,"isweb", TRUE);
  var extra = make_array("Web interface", TRUE);
  if (license)
    extra["License"] = license;
  if (build)
    extra["Build"] = build;

  register_install(
    vendor   : "Splunk",
    product  : "Splunk",
    app_name : app,
    port     : port,
    version  : version,
    path     : dir,
    extra    : extra,
    extra_no_report : extranp,
    webapp   : TRUE,
    cpe   : "cpe:/a:splunk:splunk"
  );

  report_installs(app_name:app, port:port);
}
else
{
  audit (AUDIT_WEB_APP_NOT_INST, app, port);
}
