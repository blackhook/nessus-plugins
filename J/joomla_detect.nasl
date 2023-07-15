#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21142);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");
  script_xref(name:"IAVT", value:"0001-T-0639");

  script_name(english:"Joomla! Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a content management system written in
PHP.");
  script_set_attribute(attribute:"description", value:
"Joomla!, an open source content management system written in PHP, is
running on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.joomla.org");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
include("debug.inc");

app = "Joomla!";
port = get_http_port(default:80, php:TRUE);

# Loop through directories.
dirs = make_list(cgi_dirs());
if (thorough_tests) dirs = list_uniq(make_list("/joomla", "/content", "/cms", dirs));

function check_joomla_version(url)
{
  local_var res, ver, pattern, matches;
  ver = UNKNOWN_VER;

  res = http_send_recv3(
    method       : "GET",
    item         : url,
    port         : port,
    exit_on_fail : TRUE
  );

  # newer versions of en-GB.xml include
  # the version in <version> tags, while
  # older releases will include version
  # as a <metafile> tag attribute
  if (url =~ "en-GB\.xml$" && "<version>" >< res[2])
    pattern = "<version>([0-9][^<]+)</version>";

  else if (url =~ "en-GB\.xml$")
    pattern = '<metafile version="([0-9\\.]+)"\\s+';

  else if (url =~ "english\.xml$")
    pattern = '<mosinstall version="([0-9\\.]+)"\\s+';

  else pattern = "<version>([0-9][^<]+)</version>";

  matches = pregmatch(
    pattern : pattern,
    string  : res[2]
  );

  if (!isnull(matches))
    ver = matches[1];

  # 1.0.x seem to report as 1.0.0 despite which 1.0.x version
  if (ver == "1.0.0") ver = "1.0";

  return ver;
}

installs = 0;
foreach dir (dirs)
{
  found = FALSE;
  ver = UNKNOWN_VER;

  # index.php is appended to these dirs throughout the
  # check. It should be stripped to prevent detection
  # issues.
  if ("index.php" >< dir) continue;

  # Try to pull up administrator page.
  url = dir + "/administrator/index.php";

  res = http_send_recv3(
    method       : "GET",
    item         : url,
    port         : port,
    exit_on_fail : TRUE
  );

  # If it looks like Joomla!...
  if (
    (
      "- Administration</title>" >< res[2] &&
      'name="generator" content="Joomla!' >< res[2]
    ) ||
    (res[2] =~ "- Administration \[Joomla(!)?\]\</title\>")
  )
  {
    found = TRUE;
    dbg::log(src:SCRIPT_NAME,
             msg:'Fingerprint found in '+url);
  }

  if (!found)
  {
    # filter out /administrator to avoid FPs
    if (dir =~ "^/administrator$") continue;

    # Check index page
    res2 = http_send_recv3(
      method : "GET",
      item   : dir + "/index.php",
      port   : port,
      exit_on_fail : TRUE
    );

    # Ensure to not match admin index page as this could lead to reports for
    # both the index and admin index page.
    if (
      (res2[2] =~ '<meta name="(G|g)enerator" content="Joomla(!)?') &&
      (res2[2] !~ " - Administration(\</title\>|(\s)?\[Joomla(!)?\]\</title\>)")
      &&
      (
        # Version 1.0.x
        (res2[2] =~ '(action|href)="index\\.php\\?option=com_') ||
        # Version 1.5.x
        (res2[2] =~ 'href="'+dir+'/index\\.php\\?option=com_content') ||
        # Versions 1.5.x, 1.6.x, 1.7.x, 2.5.x
        (res2[2] =~ dir + "/index\.php\?format=feed&amp;type=(atom|rss)") ||
        # Version 3.0.x, 3.1.1
        (res2[2] =~ '\\<body class="site com_content') ||
        # Version 3.5.6
        (res2[2] =~ "class='com_content")
      )
    )
    {
      found = TRUE;
      dbg::log(src:SCRIPT_NAME,
               msg:'Fingerprint found in '+dir+'/index.php');
    }
  }

  if (!found)
  {
    # finally, try via joomla.xml

    # filter out /administrator to avoid FPs
    if (dir =~ "^/administrator$") continue;

    # Try to get version for 1.6.X and above
    url = dir + "/administrator/manifests/files/joomla.xml";

    res3 = http_send_recv3(
      method : "GET",
      item   : url,
      port   : port,
      exit_on_fail : TRUE
    );

    if (preg(string:res3[2], pattern:'Joomla!') || 
        'FILES_JOOMLA_XML_DESCRIPTION' >< res3[2])
    {
      found = TRUE;
      dbg::log(src:SCRIPT_NAME,
               msg:'Fingerprint found in '+url);

      # pull also the version from joomla.xml
      pattern = "<version>([0-9][^<]+)</version>";

      matches = pregmatch(
        pattern : pattern,
        string  : res3[2]
      );

      if (!isnull(matches))
        ver = matches[1];

      # 1.0.x seem to report as 1.0.0 despite which 1.0.x version
      if (ver == "1.0.0") ver = "1.0";
    }
  }

  # retrieve version, if we don't have it yet
  if (found)
  {
    # filter out /administrator to avoid FPs
    if (dir =~ "^/administrator$") continue;

    ver_files = make_list(dir + "/administrator/manifests/files/joomla.xml",
                          dir + "/language/en-GB/en-GB.xml",
                          dir + "/language/english.xml");
    foreach url (ver_files)
    {
      if (ver != UNKNOWN_VER)
        break;

      ver = check_joomla_version(url:url);
    }

    register_install(
      vendor   : "Joomla",
      product  : "Joomla",
      app_name : app,
      path     : dir,
      port     : port,
      version  : ver,
      cpe      : "cpe:/a:joomla:joomla\!",
      webapp   : TRUE
    );
    installs++;

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}
if (installs == 0)
  audit(AUDIT_WEB_APP_NOT_INST, app, port);

# Report findings.
report_installs(port:port);

