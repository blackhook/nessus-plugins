#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53621);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/22");

  script_xref(name:"IAVT", value:"0001-T-0618");

  script_name(english:"HP SiteScope Detection");
  script_summary(english:"Checks for the presence of HP SiteScope.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a monitoring application.");
  script_set_attribute(attribute:"description", value:
"The remote host is running HP SiteScope, an agentless network
monitoring application. HP SiteScope was formerly known as Mercury
SiteScope.");
  #https://software.microfocus.com/en-us/products/sitescope-application-monitoring/overview
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67c7561c");
  script_set_attribute(attribute:"solution",value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:sitescope");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:mercury_sitescope");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microfocus:sitescope");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:micro_focus:sitescope");

  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 8080, 8443, 8888);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

version = UNKNOWN_VER;
detected = FALSE;

md5s = make_array(
  "98f9da21cfe663ec0d9864dbc379787d", "9.53",
  "78194fda0763970d876feb00450c1645", "11.10",
  "0b814fd372de5aa942fc413f845ff890", "11.11",
  "bb9f5f017aa29048820cf65966814c77", "11.12",
  "9a7991b7f9c52cd3d6ce5097977bd557", "11.13",
  "507b2f24f7a37a47b652d6c6d336cd63", "11.20",
  "767d662b6f0ee6216bcc6fdafceacc39", "11.21",
  "a3adee3d6f5856caa6c556dbf5748de1", "11.22",
  "f6bab2488d159a3883fc4cf6bf4f557b", "11.23",
  "8ea4101849e74dd3811a2f238e8038b5", "11.24",
  "395d740753c87e1de2381848a77cd5bd", "11.32",
  "c59e5147178ea5eacebb76eb5c115255", "11.33",
  "726f46fb78c0dba4220afb707b5a7c80", "11.40"
);

# By default, SiteScope serves on port 8080.
port = get_http_port(default:8080);

# Try to access page.
url = "/SiteScope";
res = http_send_recv3(
  method       : "GET",
  item         : url + "/",
  port         : port,
  exit_on_fail : TRUE
);

# If this is an older-style login page, it will contain the version
# number of the installation in the footer.
matches = pregmatch(string:res[2], pattern:"<small>SiteScope\s+([\d.]+)");
if (!isnull(matches))
{
  version = matches[1];
}

# 11.30 version information is on login page
#<div id="header" class="header-login">
#    SiteScope 11.30
#</div>
if(version == UNKNOWN_VER)
{
  matches = pregmatch(string:res[2], pattern:'header-login">[\\s]*SiteScope\\s*([\\d.]+)[\\s]*<');

  if (!isnull(matches))
    version = matches[1];
}

# 11.x login pages have the version contained in the logo.
# Compare the logo to MD5 mappings to determine version
if(version == UNKNOWN_VER)
{
  logos = [
    "/SiteScope/static/hp-style/images/SiteScope_login_Dialog_Logo.png", # Newer
    "images/ssimages/login_sitescope.gif" # Older
  ];

  css_regex = 'href="/SiteScope/static/(act|hp-style)/(stylesheets|css)/(login_hp|log-in)\\.css"';

  # Check for the SiteScope logo and CSS.
  foreach logo (logos)
  {
    # First check if the logo is in the index/login page
    if (
      '<img src="' + logo + '"' >!< res[2] ||
      !preg(string:res[2], pattern:css_regex, multiline:TRUE, icase:TRUE)
    ) continue;

    detected = TRUE;

    item = logo;
    if (logo !~ "^/SiteScope/")
      item = "/SiteScope/" + logo;

    res2 = http_send_recv3(
      method       : "GET",
      item         : item,
      port         : port,
      exit_on_fail : FALSE
    );

    if (empty_or_null(res2) || res2[0] !~ '^HTTP/[0-9.]+ +200' || empty_or_null(res2[2]))
      continue;
 
    # Get version from MD5 mappings
    md5 = hexstr(MD5(res2[2]));
    version_mapping = md5s[md5];
    if (empty_or_null(version_mapping)) continue;
    version = version_mapping;
  }
}

# The original code audited out if the version was not detected
# but we still want to detect the presence but only support
# for newer versions has been added
if (!detected && version == UNKNOWN_VER) 
  audit(AUDIT_WEB_APP_NOT_INST, "HP SiteScope", port);

installs = add_install(
  appname  : "sitescope",
  installs : NULL,
  port     : port,
  dir      : url,
  ver      : version,
  cpe      : "cpe:/a:hp:sitescope"
);

# Report findings.
report = get_install_report(
  port         : port,
  installs     : installs,
  display_name : "HP SiteScope"
);

security_report_v4(severity:SECURITY_NOTE, extra:report, port:port);
