#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44117);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"TYPO3 Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a content management system written in
PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running TYPO3, an open source content management
system written in PHP.

Note that in some cases HTTP login credentials must be supplied to detect the TYPO3 version.");
  script_set_attribute(attribute:"see_also", value:"https://typo3.org/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:typo3:typo3");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("base64.inc");
include("url_func.inc");
include("ssl_funcs.inc");

port = get_http_port(default:80, php: TRUE);

installs = 0;
app = "TYPO3";
dirs = cgi_dirs();

if (thorough_tests)
{
  dirs = make_list(dirs, '/cms', '/site', '/typo3');
  dirs = list_uniq(dirs);
}

pat = '<meta name="generator" content="TYPO3 ([0-9\\.]+)';
foreach dir (dirs)
{
  pack_ver = NULL;
  version = NULL;
  no_https = FALSE;

  url = dir + '/typo3/index.php';
  res = http_send_recv3(
    method : "GET",
    item   : url,
    port   : port,
    exit_on_fail : TRUE
  );

  if (
   preg(pattern:'<title>TYPO3( CMS)? Login', string:res[2],multiline:TRUE) ||
   preg(pattern:pat, string:res[2], multiline:TRUE)
  )
  {
    match = pregmatch(pattern:pat, string:res[2]);
    if (!empty_or_null(match))
      pack_ver = match[1];
    else pack_ver = UNKNOWN_VER;

    # Attempt to access ChangeLog to grab the version
    res2 = http_send_recv3(
      method : "GET",
      port   : port,
      item   : dir + '/typo3_src/ChangeLog',
      exit_on_fail : TRUE
    );

    match = pregmatch(
     pattern : 'Release of TYPO3 ([0-9]+\\.[^\\(\\n]+)',
     string  : res2[2]
   );

    username = get_kb_item('http/login');
    password = get_kb_item('http/password');
    version_pat = '<span class=\"topbar-header-site-version\">([0-9.]+)</span';
    if (!empty_or_null(match))
      version = match[1];
    else
    {
      # Check that the channel is encrypted
      encaps = get_port_transport(port);
      if (!empty_or_null(encaps) && encaps > ENCAPS_IP)
      {
        transport = ssl_transport(ssl:TRUE, verify:FALSE);
        # Attempt authenticated version detection for later versions using normal auth
        data = "login_status=login&userident=" + password + "&redirect_url=&loginRefresh=&interface=backend&username=" + username + "&p_field=&commandLI=";
        init_cookiejar();
        res2 = http_send_recv3(
          method       : 'POST',
          port         : port,
          item         : url,
          content_type : "application/x-www-form-urlencoded",
          data         : data,
          exit_on_fail : FALSE,
          follow_redirect : 10,
          transport    : transport
        );

        match = pregmatch(pattern: version_pat, string: res2[2]);
      }
      else
      {
        no_https = TRUE;
        spad_log(message:"Nessus will not attempt login over cleartext channel on port " + port +
            ". Please enable HTTPS on the remote host to attempt login.");
      }
    }

    if (!empty_or_null(match))
      version = match[1];
    # Try to authenticate with RSA auth, which is the default in some versions
    else
    {
      init_cookiejar();
      uri = "/typo3/index.php?ajaxID=%2Fajax%2Frsa%2Fpublickey&skipSessionUpdate=1";
      res = http_send_recv3(
        method       : 'GET',
        port         : port,
        item         : uri,
        exit_on_fail : FALSE,
        add_headers : make_array("Referer", "http://172.26.27.84/typo3/index.php")
      );

      pubkey = split(res[2], sep:':', keep:FALSE);
      n = pubkey[0];
      e = pubkey[1];
      # Only continue if a public key was received
      if (!empty_or_null(n) && !empty_or_null(e))
      {
        n_bytes = hex2raw(s:n);
        # hex2raw expects an even length string, so pad odd strings with a leading 0
        if (len(e) % 2)
          e = "0" + e;
        e_bytes = hex2raw(s:e);
        enc = rsa_public_encrypt(data:password, e:e_bytes, n:n_bytes);
        b64 = base64encode(str:enc);
        b64 = urlencode(str:b64, case_type:HEX_UPPERCASE);
        data = "login_status=login&userident=rsa%3A" + b64 + "&redirect_url=&loginRefresh=&interface=backend&username=" + username + "&p_field=&commandLI=Submit";
        uri = "/typo3/index.php";

        http_set_read_timeout(30);
        res2 = http_send_recv3(
          method       : 'POST',
          port         : port,
          item         : uri,
          content_type : "application/x-www-form-urlencoded",
          data         : data,
          exit_on_fail : FALSE,
          add_headers : make_array("Referer", "http://172.26.27.84/typo3/index.php"),
          follow_redirect: 10
        );
        match = pregmatch(pattern : version_pat, string : res2[2]);
      }
    }
    if (!empty_or_null(match))
      version = match[1];

    if (empty_or_null(version))
        version = UNKNOWN_VER;

    installs++;

    if (empty_or_null(dir))
      rep_path = "typo3/index.php";
    else
      rep_path = "/typo3/index.php";

    extra = make_array("Release Branch", pack_ver);
    if (no_https && version == UNKNOWN_VER)
      extra['Note'] = "Nessus will not attempt login over cleartext channel on port " + port +
        ". Please enable HTTPS on the remote host to attempt login and retrieve the Typo3 version.";

    register_install(
      vendor   : "Typo3",
      product  : "Typo3",
      app_name : app,
      path     : dir,
      rep_path : rep_path,
      port     : port,
      version  : version,
      cpe      : "cpe:/a:typo3:typo3",
      webapp   : TRUE,
      extra    : extra
    );

    if (!thorough_tests) break;
  }
}

if (installs == 0) audit(AUDIT_WEB_APP_NOT_INST, app, port);

report_installs(port:port);
