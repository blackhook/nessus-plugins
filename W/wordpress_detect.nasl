#TRUSTED 21f3635321763e25f9687e1aa6bea220deb1fc97f1460bfb233257a6265c8406c63ea6efca07a560202884ccbcc46029ce5d166cef41aee77ba7edf2f5597d925eca1b2360ab96f852866d9ad914da59039e75e0314c9e40b63ba98eb01d2ec62263c40034ab3b75ea996dd45978956489ee46e5a4f7f70971bc59dbda66239387b0b2c6c793b8f1c8b61d2ec7c72c05ee961cd449dfffea405664ed6191d06aa26da10f0305673e12c4d4e80cadfcff7f2728c3decfc38a48d69e1dde9ea75570073acb4710e083fed0b5ed9bab46153b3ce689fb9d90f3e771c6d67d4b46f6db33ad5da323e6bd44d7c07d009211b0d7e574f77165654dcd24bf4ce79e542b7570fd1c55af8b5a5004eddbec7a2d21ef07f27fff22fcd5e7ca4d2fd0256b4a32b522a162c9c6a2f8bc1be0596e42a4deebdfb94121ef3c5c943b893a933495e5a207aa89f67529cbb3f1bd5eeadd6fbec659142335fe8c238f372a2560c1211d43a7a2f0f06056a1390ee948162140082dcf4a07943d0048266a849dbb6d0c73a05270e3f8520bafda3bb604f77493bb8f8d9d62c940741dcaf4eb24cba8b0f019bce1d0a21e7a2d8d8a7bd7eb61e7585e993b406f2ee626b46d66dcad86332c7312ce09c628c548db48c022fc566c48d7e2d003a24e86ff5c3a41892f7c03fdf370db6f170d859cd68c09bc53536fcd425f4b522b7eef7adb0cc7991d054e
#TRUST-RSA-SHA256 2b8d50cdb551f0cced1b30919d6516e4f2b5232b04339be8bc3893718abfd779397346a49c9e80c0747b4b56f1fe5db1e78dc8c232a032333d8862ab5905dd0b64a170d3d63511bc8813e8c972cb9f0540fac0b338f39c6e88d24d82cf2eb34484ff61053162120dc0a888c77bb6f9663b88f9d057bcedcbd8d3ef07f923a2bbdbe2c12848504e3c09f1d3ecb0d9374215b748008a4843cd0a950c801cef7800299ac5e41529ae1d48144f46f57b80f97f2f9122ae075789d92754c0de04f68a126ff63b62a385544ae0a432d003ac2a605a14cf128b50dec36dd9afdb56af4da3fcede9c192c2fd328b6942f185cefc39f568887167d59a81a8a383d5d22e2b73758628d86d572be0100c6b4c58aaf9d1308b22d2c789aac747eaaca3c6269bba755cdc42e7272d95331df2f90222523afc4e37db450356f6c0cc4bf2c17613896fd998c6d0ca34b5f5bcde5a9739671e0b36c3694c1a97fe2e3e9244e2d99c95b58839b861ad56d648687e67afc6732202cf883a01e14cff4390f59e257c55cb76f7533897a91e0ce83b3a8e792365167b697edaa0d727822965c361f96a9b2d7886bab7ec20fabd75102f9ad359ef0255300b339f001fa94beecb18283e1ead4fc5d1056ee9ea151226c72e560b16522d7f8c0a111e039e9d9fe8ad74a48ad9f936f94595ff8b694bbdba511d918fd786743d7f3a12df8e2daa80f31ea904
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(18297);
  script_version("1.34");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_xref(name:"IAVT", value:"0001-T-0747");

  script_name(english:"WordPress Detection");

  script_set_attribute(attribute:"synopsis", value:"The remote web server contains a blog application written in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running WordPress, a free blog application written
in PHP with a MySQL back-end.");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('install_func.inc');
include('debug.inc');

# Parse a redirect and grab the location if the redirect
# is used for language support
function check_wp_redirect(res, dir)
{
  var loc, parse_loc, redir;

  if (
    (preg(pattern:"lang", string:res[1], icase:TRUE, multiline:TRUE)) ||
    (preg(pattern:"translate", string:res[2], icase:TRUE, multiline:TRUE))
  )
  {
    loc = egrep(string:res[1], pattern:'^Location:', icase:1);
    if (empty_or_null(loc)) return NULL;

    parse_loc = pregmatch(
      string  : chomp(loc),
      pattern : '^Location:[ \t]*([^ \t].*)',
      icase   : TRUE
    );
    if (empty_or_null(parse_loc)) return NULL;

    # /blog/en/
    redir = pregmatch(pattern:"(" + dir + "/[a-zA-Z]{2}/)", string:parse_loc[1]);
    if (!isnull(redir) && !empty_or_null(redir[1]))
    {
      redir = redir[1];
      return redir;
    }
    else
    {
      # /blog/?lang=en
      redir = pregmatch(pattern:"(" + dir + "/\?lang=[a-zA-Z]{2})", string:parse_loc[1]);
      if (!isnull(redir) && !empty_or_null(redir[1]))
      {
        redir = redir[1];
        return redir;
      }
    }
  }
  return NULL;
}

# Test the redirect URL we obtained above and ensure
# we get a 200 response, otherwise we will just keep the
# original response to the initial request and parse that.
function parse_wp_redirect(res, dir)
{
  var test_res = http_send_recv3(method:'GET', port:port, item:dir, exit_on_fail:TRUE);
  dbg::log(msg:'Request:\n' + http_last_sent_request());
  dbg::log(msg:'Response:\nSTATUS:\n' + test_res[0] + '\nHEADERS:\n' + test_res[1] + '\nBODY:\n' + test_res[2]);
  if (res[0] =~ '^HTTP/1\\.[01] +200') return test_res;
  return res;
}

var port = get_http_port(default:80, php: TRUE);

# Loop through directories.
var dirs = list_uniq(make_list('/wordpress', '/blog', cgi_dirs()));
var installs = 0;
var pre_dir, pre_dir1, new_dir, matches, match, found, backup_chk, extra, res, ver, pat, item;
foreach var dir (sort(dirs))
{
  # Check to make sure we don't flag an install under a previous directory
  # name to prevent double reporting a single install in cases where
  # permalinks are not set to 'Default'
  if (pre_dir)
    pre_dir1 = ereg_replace(pattern:"(/[^/]+/).*", string:pre_dir, replace:"\1");

  new_dir = ereg_replace(pattern:"(/[^/]+/).*", string:dir, replace:"\1");
  if (pre_dir1 && preg(pattern:"^" + pre_dir1 + "/", string:new_dir + '/')) continue;

  found = FALSE;
  backup_chk = FALSE;
  extra = NULL;
  res = http_send_recv3(method:'GET', item:dir + '/', port:port, exit_on_fail:TRUE);
  dbg::log(msg:'Request:\n' + http_last_sent_request());
  dbg::log(msg:'Response:\nSTATUS:\n' + res[0] + '\nHEADERS:\n' + res[1] + '\nBODY:\n' + res[2]);
  if (res[0] =~ '^HTTP/1\\.[01] +30[1237] ')
  {
    redir_path = check_wp_redirect(res:res, dir:dir);
    if (!isnull(redir_path))
    {
      extra['Redirect'] = redir_path;
      res = parse_wp_redirect(res:res, dir:redir_path);
    }
  }

  ver = UNKNOWN_VER;

  if (egrep(pattern:"src=('" + '|")([a-zA-Z0-9\\./_:-]+)/wp-content/themes/', string:res[2]) ||
      egrep(pattern:'\\<link rel=("|' + "')wlwmanifest('|" + '") type=("|' + "')application/wlwmanifest\+xml('|" + '")', string:res[2]) ||
      egrep(pattern:"<link rel=('|" + '")pingback("|' + "')", string:res[2]))
    backup_chk = TRUE;

  # Try to identify the version number from the Generator meta tag.
  pat = '<meta name="generator" content="WordPress (\\d+\\.\\d+\\.\\d+)" />';
  matches = egrep(pattern:pat, string:res[2]);
  if (matches)
  {
    foreach match(split(matches, keep:FALSE))
    {
      item = pregmatch(pattern:pat, string:match);
      if (item)
      {
        found = TRUE;
        ver = item[1];
        break;
      }
    }
  }

  # If that didn't work, look in readme.html.
  if (!matches && backup_chk)
  {
    res2 = http_send_recv3(method:'GET', item:dir + '/readme.html', port:port, exit_on_fail:TRUE);
    dbg::log(msg:'Request:\n' + http_last_sent_request());
    dbg::log(msg:'Response:\nSTATUS:\n' + res2[0] + '\nHEADERS:\n' + res2[1] + '\nBODY:\n' + res2[2]);
    if ('<title>WordPress' >< res2[2])
    {
      found = TRUE;
      pats = make_list('^\\s+Version (.+)</h1>','^\\s+<br /> Version (.+)');
      foreach pat (pats)
      {
        matches = egrep(pattern:pat, string:res2[2]);
        if (matches)
        {
          foreach match (split(matches, keep:FALSE))
          {
            item = pregmatch(pattern:pat, string:match);
            if (!isnull(item))
            {
              ver = item[1];
              break;
            }
          }
        }
      }
    }
  }

  if (!found && backup_chk)
  {
    # Check /wp-includes/js/quicktags.js.  File existed since 2.0
    pat1 = 'new edLink\\(("|' + "'" + ')WordPress("|' + "')";
    pat2 = 'new edLink\\(("|' + "'" + ')alexking.org("|' + "')";

    res = http_send_recv3(method:'GET', item:dir + '/wp-includes/js/quicktags.js', port:port, exit_on_fail:TRUE);
    dbg::log(msg:'Request:\n' + http_last_sent_request());
    dbg::log(msg:'Response:\nSTATUS:\n' + res[0] + '\nHEADERS:\n' + res[1] + '\nBODY:\n' + res[2]);
    if (( egrep(pattern:pat1, string:res[2]) && egrep(pattern:pat2, string:res[2]) ) || '* This is the HTML editor in WordPress' >< res[2])
      found = TRUE;
    else
    {
      # Check /wp-includes/js/quicktags.dev.js. Some cases such as 3.3.x and
      # 3.4.x versions contained more identifiable tags in this file instead
      res = http_send_recv3(method:'GET', item:dir + '/wp-includes/js/quicktags.dev.js', port:port, exit_on_fail:TRUE);
      dbg::log(msg:'Request:\n' + http_last_sent_request());
      dbg::log(msg:'Response:\nSTATUS:\n' + res[0] + '\nHEADERS:\n' + res[1] + '\nBODY:\n' + res[2]);

      if ((egrep(pattern:pat1, string:res[2]) && egrep(pattern:pat2, string:res[2])) ||
          ('* This is the HTML editor in WordPress' >< res[2] && 'http://www.alexking.org' >< res[2]))
        found = TRUE;
    }
  }

  if (found)
  {
    register_install(
      vendor   : 'WordPress',
      product  : 'WordPress',
      app_name : 'WordPress',
      path     : dir,
      port     : port,
      version  : ver,
      cpe      : 'cpe:/a:wordpress:wordpress',
      webapp   : TRUE,
      extra_no_report : extra
    );
    installs++;
    pre_dir = dir;
  }
}

if (installs == 0) audit(AUDIT_WEB_APP_NOT_INST, 'WordPress', port);

# Report findings.
report_installs(port:port);
