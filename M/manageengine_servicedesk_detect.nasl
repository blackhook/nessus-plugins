##
# (C) Tenable Network Security, Inc.
##


include("compat.inc");


if (description)
{
  script_id(55444);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_name(english:"ManageEngine ServiceDesk Plus Detection");
  script_summary(english:"Checks for evidence of ManageEngine ServiceDesk.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a help desk management application.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts ManageEngine ServiceDesk Plus, a web-based
help desk management application written in Java.");
  script_set_attribute(attribute:"see_also", value:"https://www.manageengine.com/help-desk-software.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_servicedesk_plus");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_servicedesk_plus_msp");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("http.inc");
include("webapp_func.inc");

var port = get_http_port(default:8080);
var installs = [], url = '/', version = UNKNOWN_VER;
var pattern, match, matches, item, product=NULL, version_pattern, key, extra={};

var res = http_get_cache(item:url, port:port, exit_on_fail:TRUE);

var patterns = {
  'ManageEngine ServiceDesk Plus': "title>.*ManageEngine ServiceDesk Plus(?!\s)",
  'ManageEngine ServiceDesk Plus MSP': "title>.*ManageEngine ServiceDesk Plus\s+-\s+MSP"
};

# There are two parts to a version -- the main version that's
# visible and a build, which only seems to be included in URLs.
var build_pat = "'/scripts/Login\.js\?([0-9]+)'";
var version_patterns = ["ManageEngine ServiceDesk.+?(?<=')([0-9]+\.[^<']+)(<|')",
                    "'http://www.manageengine.com/products/service-desk/index.html','([0-9]+.[0-9]+)'"];

foreach key (keys(patterns))
{
  if (pgrep(pattern:patterns[key], string:res))
  {
    # find version
    foreach version_pattern (version_patterns)
    {
      matches = pgrep(pattern:version_pattern, string:res);
      if (empty_or_null(matches)) continue;

      foreach match (split(matches, keep:FALSE))
      {
        item = pregmatch(pattern:version_pattern, string:match);
        if (empty_or_null(item) || empty_or_null(item[1])) continue;
        version = item[1];

        # find build
        matches = pgrep(pattern:build_pat, string:res);
        if (!empty_or_null(matches))
        {
          foreach match (split(matches, keep:FALSE))
          {
            item = pregmatch(pattern:build_pat, string:match);
            if (empty_or_null(item)) continue;

            version += ' Build ' + item[1];
            break;
          }
        }
        if (version != UNKNOWN_VER) break;
      }
      if (version != UNKNOWN_VER) break;
    }
  }
  if (version != UNKNOWN_VER)
  {
    product = key;
    break;
  }
}

if (isnull(product))
  exit(0, 'ManageEngine ServiceDesk Plus was not detected on the web server on port '+port+'.');

# check if SSO is enabled
var sso_pattern = ">Log in with SAML Single Sign On</a>";
if (preg(pattern:sso_pattern, string:res, multiline:true))
  extra['SSO Login Enabled'] = 'True';

if ( product == 'ManageEngine ServiceDesk Plus' )
{
  extra['Product'] = 'ManageEngine ServiceDesk Plus';
  cpe = 'cpe:/a:zohocorp:manageengine_servicedesk_plus';
}
else
{
  extra['Product'] = 'ManageEngine ServiceDesk Plus MSP';
  cpe = 'cpe:/a:zohocorp:manageengine_servicedesk_plus_msp';
}

# Save info about the install.
installs = add_install(
  appname  : 'manageengine_servicedesk',
  installs : installs,
  port     : port,
  dir      : '',
  ver      : version,
  cpe      : cpe,
  extra    : extra
);

# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    item         : url,
    display_name : product
  );
  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
}
else
{
  security_report_v4(port:port, severity:SECURITY_NOTE);
}
