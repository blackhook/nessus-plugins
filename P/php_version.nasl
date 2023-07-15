#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48243);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");
  script_xref(name:"IAVT", value:"0001-T-0936");

  script_name(english:"PHP Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to obtain the version number of the remote PHP
installation.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to determine the version of PHP available on the
remote web server.");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "phpinfo.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("backport.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "PHP";
cpe = "cpe:/a:php:php";

get_kb_item_or_exit("www/PHP");

port = get_http_port(default:80, php:TRUE);

source  = NULL;
version = NULL;
installs = make_array();

banner = get_http_banner(port:port);
if (!isnull(banner))
{
  # Identify the source header line and version info.
  pat = '^(Server|X-Powered-By):.*PHP/([0-9][^ ]+)';

  matches = pgrep(string:banner, pattern:pat);
  if (matches)
  {
    foreach line (split(matches, keep:FALSE))
    {
      backported = FALSE;
      item = pregmatch(pattern:pat, string:line);
      if (!isnull(item))
      {
        source = line;
        version = item[2];

        # Determine if it's been backported.
        get_php_version(banner:line);

        if (backported)
          set_kb_item(name: 'www/php/'+port+'/'+version+'/backported', value:TRUE);

        #reporting
        installs[version] += source + ', ';
      }
    }
  }
}

if (max_index(keys(installs)) == 0)
{
  # Get version from webmirror if banner check fails
  version = get_kb_item("www/"+port+"/webmirror_php_version");
  if (!isnull(version))
  {
    source = get_kb_item("www/"+port+"/webmirror_php_source");
    # Should not occur
    if (isnull(source)) source = 'X-Powered-By server header';

    # Determine if it's been backported.
    get_php_version(banner:source);

    if (backported)
      set_kb_item(name: 'www/php/'+port+'/'+version+'/backported', value:TRUE);

    #reporting
    installs[version] += source + ', ';
  }
}

# Check for version info from phpinfo.nasl and extract unique values
vers = get_kb_list('www/phpinfo/'+port+'/version/*');
if (!isnull(vers))
{
  foreach ver (list_uniq(keys(vers)))
  {
    backported = FALSE;
    version = ereg_replace(
      pattern : 'www/phpinfo/[0-9]+/version/',
      replace : '',
      string  : ver
    );
    dir = pregmatch(pattern: "under (.+)", string:vers[ver]);
    if (!isnull(dir)) source = dir[1];

    # Is version backported?
    if (version =~ "[0-9]+")
    {
      banner = "X-Powered-By: PHP/" + version;
      get_php_version(banner:banner);
    }

    if (backported)
      set_kb_item(name:'www/php/'+port+'/'+version+'/backported', value:TRUE);

    #reporting
    installs[version] += source + ', ';
  }
}
if (isnull(source))
  exit(0, "There is no mention of PHP in the 'Server' and/or 'X-Powered-By' response headers or from a phpinfo() page from the web server listening on port " + port + ".");

# Sort unique versions and add to KB / report output
report = '\nNessus was able to identify the following PHP version ' +
  'information :\n';

foreach version (sort(keys(installs)))
{
  path = "/";
  extra = {};

  set_kb_item(
      name  : 'www/php/'+port+'/version',
      value : version + ' under ' + installs[version]
    );
  report += '\n  Version : ' + version + '\n';

  # Sources example: 'X-Powered-By: PHP/7.2.14, http://phphost/info.php, '
  sources_str = installs[version];

  # Remove delimiter ', ' at the end
  sources_str = ereg_replace(pattern:', $', replace:'', string:sources_str);

  extra['Source'] = sources_str;

  # Since multiple versions can be installed on the same instance and
  # app along w/ the path need to be unique, append version and source to the path
  # path example: '/ (7.2.14 under X-Powered-By: PHP/7.2.14, http://phphost/info.php)'
  path += " (" + version + " under " + sources_str + ")";

  sources = split(installs[version],sep:', ', keep:FALSE);
  foreach source (sort(sources))
  {
    report += '  Source  : ' + source + '\n';
  }

  register_install(
   app_name : app,
   vendor : 'PHP',
   product : 'PHP',
   version  : version,
   path     : path,
   port     : port,
   extra    : extra,
   cpe      : cpe
  );
}

security_report_v4(severity:SECURITY_NOTE, extra:report, port:port);
