###
# (C) Tenable Network Security, Inc.
###

include("compat.inc");

if (description)
{
  script_id(18638);
  script_version("1.35");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");
  script_xref(name:"IAVT", value:"0001-T-0586");

  script_name(english:"Drupal Software Detection");

  script_set_attribute(attribute:"synopsis", value:
"A content management system is running on the remote web server.");
  script_set_attribute(attribute:"description", value:
"Drupal, an open source content management system written in PHP, is
running on the remote web server.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/");
  script_set_attribute(attribute:"solution", value:
"Ensure that the use of this software aligns with your organization's
security and acceptable use policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("debug.inc");

port = get_http_port(default:80, php:TRUE);
app = "Drupal";

function drupal_version_from_header( res )
{
  # look in header before we toss result for 'X-Generator: Drupal 8'
  local_var matches = pregmatch(pattern:'Drupal ([0-9\\.]+)', string:res[1]);
  if (!empty_or_null(matches))
  {
    return matches[1];
  }
  return NULL;
}

function drupal_version_from_md5( md5 )
{
  local_var ver_lookup = make_array(
  "dc0fbe017fd1cc3d97b8c12bc45dde41", "4.7.0 4.7.1",
  "98cd0c4c8bde66a3227ce1d583f433f4", "4.7.2 4.7.3",
  "3130d555431177091ff7ac5b4f3fe19e", "4.7.4",
  "dd465695d5ae35ecc33c8cad33f7880c", "4.7.5 4.7.6 4.7.7 4.7.8 4.7.9 4.7.10 4.7.11",
  "afd188dc6cd982d37463209679ab01ec", "5.0 5.1",
  "9e557006e956d365119eb2ebd2169051", "5.2 5.3 5.4 5.5 5.6 5.7 5.8 5.9",
  "2c5e4277fec6afac333e913744e0408f", "5.10 5.11 5.12 5.13 5.14 5.15 5.16",
  "4677b027fed107133090dabccee2b4f5", "5.17 5.18 5.19 5.20 5.21 5.22 5.23",
  "ebbcc0156242a08a25c596432ca92f67", "6.0",
  "2ff7dc985e57d1139ce4dc844b06bc64", "6.1 6.2",
  "398b3832c2de0a0ebd08cb7f2afe1545", "6.3 6.4 6.5 6.6 6.7 6.8 6.9 6.10 6.11 6.12 6.13",
  "88682723723be277fb57c0d8e341c0cf", "6.14 6.15 6.16 6.17 6.18 6.19 6.20",
  "9a1c645566d780facee5ce1a0d3fab7c", "6.21",
  "fe6f8c678cb511d68a3dbe5a94f2e278", "6.22 6.23",
  "90c0aa7ed8581884c2afe73fc87b5697", "6.24 6.25 6.26 6.27",
  "1904f6fd4a4fe747d6b53ca9fd81f848", "6.28 6.29 6.30 6.31 6.32 6.33 6.34 6.35 6.36 6.37 6.38",
  "847afc6e14d280e66a564194e166a66e", "7.0",
  "f3f32021901f4c33d2eebbc634de587d", "7.1",
  "cea76de12c5bb95dd0789fbd3cd754f0", "7.2 7.3 7.4 7.5 7.6 7.7 7.8",
  "d4515f21acd461ca04304233bf0daa1e", "7.9 7.11",
  "cbd95e04bad1be13320ebbe63a863245", "7.10",
  "f9281a1fa8b926ba038bebc3bb0c3d61", "7.12 7.13 7.14 7.15 7.16 7.17 7.18",
  "0bb055ea361b208072be45e8e004117b", "7.19 7.20 7.21 7.22 7.23 7.24 7.25 7.26 7.27 7.28 7.29 7.30 7.31 7.32 7.33 7.34 7.35 7.36 7.37 7.38",
  "bb9f18fb7a42b95fcad87b98dbb19c87", "7.39 7.40 7.41 7.42 7.43 7.44 7.50",
  "acf092762cf1cf821a12325fbf494ecf", "7.51 7.52 7.53 7.54",
  "ce89aafcde644262269009c10d8a9cd2", "7.55 7.56",
  "a4065c93addf975e695586c24a20bda8", "7.57 7.58 7.59 7.60",
  "3dcbe8b1280a271797fe4f1dd5700d0c", "8.0.0 8.0.1 8.0.2 8.0.3 8.0.4 8.0.5 8.0.6",
  "714d7aeb86ea12acc0de88e2b135f14d", "8.1.0 8.1.1 8.1.2 8.1.3 8.1.4 8.1.5 8.1.6 8.1.7 8.1.8 8.1.9 8.1.10 8.2.0 8.2.1 8.2.2 8.2.3 8.2.4 8.2.5 8.2.6 8.2.7 8.2.8",
  "0e18a6096f1a222fab718c153266444a", "8.3.0 8.3.1 8.3.2 8.3.3 8.3.4 8.3.5 8.3.6 8.3.7",
  "5ef71c6e30d110e9e329c3f7531bb285", "8.3.8 8.3.9",
  "423a643a05f801dea5358481e56d83d7", "8.4.0 8.4.1 8.4.2 8.4.3 8.4.4",
  "767df16aa36ccaa000a195ff5680a9c2", "8.4.5 8.4.6 8.4.7 8.4.8",
  "71bfba813a9f85564220f8e9a1b06da4", "8.5.0 8.5.1 8.5.2 8.5.3 8.5.4 8.5.5 8.5.6 8.5.7 8.5.8",
  "a375001d7040601a26da55bd8c30856d", "8.6.0 8.6.1 8.6.2",
  "ae9cceaa80684c10cdff035fc27fa4de", "9.0.0 9.0.1 9.0.2 9.0.3 9.0.4 9.0.5 9.0.6 9.0.7 9.1.0 9.1.1 9.1.2 9.1.3 9.1.4 9.1.5 9.1.6 9.1.7 9.1.8 9.1.9 9.2.0 9.2.1 9.2.2 9.2.3 9.2.4 9.2.5 9.2.6"
  );

  # find md5 of drupal.js in lookup table
  local_var jsver = ver_lookup[ md5 ];
  if ( isnull( jsver ) )
  {
    # not found, nothing to report
    return NULL;
  }
  # found, how many versions have this md5 value?
  local_var jsvers = split( jsver, sep:" ", keep:FALSE );
  # only one?
  if ( max_index( jsvers ) == 1 )
  {
    # only one, report this specific version
    return make_list( jsvers, NULL );
  }
  # more than one, report a generic version and note about what it might be
  return make_list( substr(jsver,0,0), 'The version appears to be ' + jsver + ' according to the MD5 of drupal.js'  );
}

# always check root and /drupal
var dirs = make_list('', '/drupal');

if (!get_kb_item('Settings/disable_cgi_scanning'))
{
  dirs = make_list(dirs, cgi_dirs());
  dirs = list_uniq(dirs);
}

installs = 0;
var dir;
foreach dir (dirs)
{
  ver = UNKNOWN_VER;
  altver = UNKNOWN_VER;
  found = FALSE;
  url = dir + "/";
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
  # /search/node FP
  match = pregmatch(string:res[2], pattern:'name="Generator" content="Drupal (8|9)');
  if (!empty_or_null(match) && '<h3>Your search yielded no results' >!< res[2])
  {
    found = TRUE;
    altver = match[1];
    url = dir + "/core/install.php";
    res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:FALSE);
    matches = pregmatch(pattern:'<span class="site-version">([0-9\\.a-z-]+)</span>', string:res[2]);
    dbg::log(src:SCRIPT_NAME, msg:" Drupal found via site version tag ");

    if (!empty_or_null(matches))
    {
      ver = matches[1];
    }
  }
  else
  {
    match = pregmatch(string:res[2], pattern:'<meta name="generator" content="Drupal ([0-9])', icase:TRUE);
    # Simple check of the index page
    if (!empty_or_null(match) && "Drupal.settings" >< res[2] && "/drupal.js" >< res[2])
    {
      found = TRUE;
      altver = match[1];
      dbg::log(src:SCRIPT_NAME, msg:" Drupal found via meta tag ");
    }
    # Index page doesn't appear to be running on Drupal, check 'update.php'
    if (!found)
    {
      url = dir + "/update.php?op=info";
      res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:FALSE);
      # If it looks like Drupal...
      if (
        (
          "main Drupal directory" >< res[2] &&
          (
            "<code>$access_check = FALSE;</code>" >< res[2] ||
            "<code>$update_free_access = FALSE;</code>" >< res[2]
          ) ||
          "set $update_free_access" >< res[2]
        ) ||
        "<h1>Drupal database update</h1>" >< res[2]
      )
      {
        found = TRUE;
        altver = drupal_version_from_header( res:res );
        dbg::log(src:SCRIPT_NAME, msg:" Drupal Found via update.php ");
      }
    }
    # update.php doesn't appear to be running on Drupal, check 'misc/drupal.js'
    var drupaljs_dir;
    if (!found)
    {
      var drupaljs_dirs = list_uniq(make_list("/misc", "/core/misc"));
      foreach drupaljs_dir (drupaljs_dirs)
      {
        url = dir + drupaljs_dir + "/drupal.js";
        res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:FALSE);
        if (
          res[0] =~ '^HTTP/[0-9.]+ +200' &&
          "var Drupal = Drupal" >< res[2] &&
          "Drupal.attachBehaviors = function" >< res[2] && "Drupal.detachBehaviors = function" >< res[2]
        )
        {
          found = TRUE;
          dbg::log(src:SCRIPT_NAME, msg:" Drupal Found via Drupal.js contents ");

        }
        if ( res[0] =~ '^HTTP/[0-9.]+ +200' )
        {
          md5ver = drupal_version_from_md5( md5:hexstr(MD5(res[2])) );
          if ( empty_or_null( md5ver ) )
          {
            # header detection of version is very weak and last resort
            altver = drupal_version_from_header( res:res );
          }
          else
          {
            # some versions of drupal.js won't match detachBehaviors, but match md5 here
            found = TRUE;
            dbg::log(src:SCRIPT_NAME, msg:" Drupal Found via Drupal.js + MD5 ");
            altver = md5ver[0];
            note = md5ver[1];
          }
          break;
        }
      }
    }
    if (!found) continue;
    # Try to identify the version number from the changelog.
    # Starting with 8.0, CHANGELOG.txt has moved to core/
    changelog = make_list("/", "/core/");
    var path, match;
    foreach path (changelog)
    {
      url = dir + path + "CHANGELOG.txt";
      url = ereg_replace(string:url, pattern: "//+", replace: "/");
      res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:FALSE);
      # nb: Drupal 1.0.0 was the first version, released 2001-01-15.
      pat = "^Drupal +([1-9].+), 20";
      matches = pgrep(pattern:pat, string:res[2]);
      if (!empty_or_null(matches))
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
  if (found)
  {
    if ( ( ver == UNKNOWN_VER ) && ( altver != UNKNOWN_VER ) )
    {
      ver = altver;
    }
    extra = NULL;
    if ( !empty_or_null(note) )
    {
      extra = make_array( "Note", note );
    }
    register_install(
      vendor   : "Drupal",
      product  : "Drupal",
      app_name : app,
      path     : dir,
      port     : port,
      version  : ver,
      cpe      : "cpe:/a:drupal:drupal",
      extra    : extra,
      webapp   : TRUE
    );
    installs++;

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}
if (installs == 0) audit(AUDIT_WEB_APP_NOT_INST, app, port);
report_installs(port:port);
