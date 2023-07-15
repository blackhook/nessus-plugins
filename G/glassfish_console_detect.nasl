#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55929);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/22");

  script_name(english:"Oracle GlassFish Server Administration Console");
  script_summary(english:"Detects the presence of the Oracle GlassFish Admin Console.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to access the administration console of the remote
Oracle GlassFish application server.");
  script_set_attribute(attribute:"description", value:
"The remote host is running the Oracle GlassFish application server,
and has the administration console listening on an external IP.");
  # http://www.oracle.com/us/products/middleware/cloud-app-foundation/glassfish-server/overview/index.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?85f4fd5a");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("glassfish_detect.nasl");
  script_require_keys("www/glassfish");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("glassfish.inc");

#
# Main
#

# Check that GlassFish is detected
get_kb_item_or_exit('www/glassfish');

# By default, GlassFish's administration console listens on port 4848.
port = get_glassfish_port(default:4848);

# Look for snippets of the administration console.
res = join(get_glassfish_res(url:'/login.jsf', port:port));

# 1. Check for consol if it's up and running (GlassFish 3.X, 4.X, 5.X)
# 2. Check for consol if it's first time we access it (GlassFish 4.X, 5.X - pops wait for loading page)
if ( ("<title>Login</title>" >!< res || res !~ 'title="Log In to.*(GlassFish|Sun Java System Application Server)') && 
     ("not yet loaded" >!< res || "GlassFish Server Administration Console" >!< res) )
  audit(AUDIT_NOT_DETECT, "Oracle GlassFish Server Administration Console");

set_kb_item(name:"www/glassfish/console", value:TRUE);
set_kb_item(name:"www/" + port + "/glassfish/console", value:TRUE);

report = '\nOracle GlassFish Server Administration Console detected on port ' + port + '.\n';

security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
exit(0);
