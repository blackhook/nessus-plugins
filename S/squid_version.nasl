#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49692);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"Squid Proxy Version Detection");
  script_summary(english:"Obtains the version of the remote Squid proxy server.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to obtain the version number of the remote Squid proxy
server.");
  script_set_attribute(attribute:"description", value:
"The remote host is running the Squid proxy server, an open source
proxy server. It was possible to read the version number from the
banner.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/28");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2010-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("proxy_use.nasl");
  script_require_ports("Services/http_proxy", 3128, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");

app_name = "Squid";

function local_get_squid_banner(port)
{
  local_var r, lines, pat;
  if (!get_port_state(port)) return NULL;
  r = http_get_cache(item:"/", port:port);
  if (isnull(r)) return NULL;

  pat = '^Server: [Ss]quid(/[0-9]\\.[^ \\)]+)?';
  lines = pgrep(pattern:pat, string:r);
  if (!lines)
  {
    # Check a second pattern if the Server header is missing.
    pat = 'Generated [A-Za-z]+, [0-9]{1,2} [A-Za-z]+ [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} [A-Za-z]+ by [^\\(]+\\([Ss]quid(\\/[0-9\\.]+[^\\)]+)?\\)';
    if (
      'X-Squid-Error: ' >< r ||
      '<TITLE>Error: The requested URL could not be retrieved</TITLE>' >< r
    )
    lines = pgrep(pattern:pat, string:r);
    if (!lines) return NULL;
  }

  foreach r (split(lines, keep:FALSE));
  {
    if (pregmatch(pattern:pat, string:r)) return r;
  }
  return NULL;
}


squidfound=0;

kb_list = get_kb_list("Services/http_proxy");

if (isnull(kb_list)) ports = make_list();
else ports = make_list(kb_list);

foreach p (make_list(3128, 8080))
{
  if (service_is_unknown(port:p))
  {
    ports = add_port_in_list(list:ports, port:p);
  }
}
if (max_index(ports) == 0) audit(AUDIT_NOT_LISTEN, app_name, p);

foreach p (ports)
{
  # Get the Squid banner
  banner = local_get_squid_banner(port:p);
  if (!isnull(banner))
  {
    squidfound=1;
    if (isnull(get_kb_item('www/squid'))) set_kb_item(name:'www/squid', value:TRUE);
    set_kb_item(name:'http_proxy/'+p+'/squid', value:TRUE);

    version = ereg_replace(pattern:'(^Server: |.*Generated.*by.*)[Ss]quid/([0-9]+\\.[^ \\)]+).*', replace:"\2", string:banner);
    # If the version info is available
    if (version =~ '^[0-9]+\\..+')
    {
      set_kb_item(name:'http_proxy/'+p+'/squid/source', value:banner);
      set_kb_item(name:'http_proxy/'+p+'/squid/version', value:version);
    }

    register_install(
      vendor   : "Squid-cache",
      product  : "Squid",
      app_name : app_name,
      path     : "/",
      port     : p,
      version  : version,
      cpe      : "cpe:/a:squid-cache:squid",
      webapp   : TRUE,
      extra    : make_array("Source", banner)
    );
  }
}
if (squidfound == 0)
  audit(AUDIT_NOT_DETECT, app_name, p);

report_installs(port:p);
