#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57975);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_name(english:"Kayako SupportSuite Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a customer support system written in
PHP.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running Kayako SupportSuite, a customer
support application written in PHP.");
  script_set_attribute(attribute:"see_also", value:"https://www.kayako.com/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kayako:supportsuite");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/support", "/helpdesk", "/help", "/kayako", "/esupport", "/supportsuite", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  ver = NULL;
  url = dir + "/index.php";
  res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

  if (egrep(pattern:"<title.*(Powered [Bb]y Kayako SupportSuite|Kayako SupportSuite Help Desk Software)", string:res[2]))
  {
    # Try to extract the version number
    vmatches = eregmatch(pattern:"(<span.*)?href.*kayako\.com.*target=._blank.*Kayako SupportSuite( v([0-9.]+))?", string:res[2]);

    if (!isnull(vmatches[3])) ver = vmatches[3];
    else
    {
      # See if information can be pulled from admin/index.php
      url = dir + "/admin/index.php";
      res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);
  
      if (">Powered by SupportSuite<br/>" >< res[2])
      {
        vmatches = eregmatch(pattern:"<td width=.144. align=.left.*<font.*>([0-9.]+)<\/font>", string:res[2]);
        # Try to extract the version number
        if (!isnull(vmatches[1])) ver = vmatches[1];
      }
    }

    installs = add_install(
      appname  : "kayako_supportsuite", 
      installs : installs, 
      dir      : dir, 
      ver      : ver, 
      port     : port, 
      cpe     : "cpe:/a:kayako:supportsuite"
    );

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if ((max_index(keys(installs)) > 0) && !thorough_tests) break;
  }
}

# Report the findings.
if (max_index(keys(installs)) > 0)
{
  if (report_verbosity >0)
  {
    report = get_install_report(
      display_name : "Kayako SupportSuite", 
      installs     : installs, 
      port         : port 
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
} 
else audit(AUDIT_WEB_FILES_NOT, "Kayako SupportSuite", port);
