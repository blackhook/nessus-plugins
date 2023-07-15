#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56979);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");
  script_xref(name:"IAVT", value:"0001-T-0698");

  script_name(english:"Oracle WebLogic Detection (Combined)");

  script_set_attribute(attribute:"synopsis", value:
"Oracle WebLogic is running on the remote web server.");
  script_set_attribute(attribute:"description", value:
"Oracle (formerly BEA) WebLogic, a Java EE application server, is
running on the remote web server.");
  # https://www.oracle.com/middleware/technologies/weblogic.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2b4620b");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bea:weblogic_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "t3_detect.nasl", "ldap_detect.nasl", "weblogic_www_detect.nasl", "oracle_weblogic_snmp_detect_tcp.nasl");
  script_require_ports("www/weblogic", "Services/t3", "snmp/weblogic", 80, 7001, 7002, 9002);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc"); 
include("t3.inc");
include("install_func.inc");

appname = "WebLogic";
app_cpe = "cpe:/a:oracle:weblogic_server";

# We should have seen WebLogic via HTTP, SNMP, T3, or LDAP. We now need to combine
# that data. Start with www. We've decided to trust the version there over the t3
# and snmp version banners

www_ports = get_kb_list("www/weblogic/ports");
if (!empty_or_null(www_ports))
{
  www_ports = list_uniq(www_ports);
  foreach port (www_ports)
  {
    set_kb_item(name:"weblogic/ports", value:port);
    set_kb_item(name:"weblogic/" + port + "/protocols", value:'www');

    version = get_kb_item("www/weblogic/" + port + "/version");
    if (!empty_or_null(version))
    {
      replace_kb_item(name:"weblogic/" + port + "/version", value:version);
      replace_kb_item(name:"weblogic/" + port + "/version_source", value:'www');
    }
  }
}

snmp_ports = get_kb_list("snmp/weblogic/ports");
if (!empty_or_null(snmp_ports))
{
  snmp_ports = list_uniq(snmp_ports);
  foreach port (snmp_ports)
  {
    set_kb_item(name:"weblogic/ports", value:port);
    set_kb_item(name:"weblogic/" + port + "/protocols", value:'snmp');

    if (empty_or_null(get_kb_item("weblogic/" + port + "/version")))
    {
      # if we didn't get a version via WWW then add the t3 value
      version = get_kb_item("snmp/weblogic/" + port + "/version");
      if (!empty_or_null(version))
      {
        replace_kb_item(name:"weblogic/" + port + "/version", value:version);
        replace_kb_item(name:"weblogic/" + port + "/version_source", value:'snmp');
      }
    }
  }
}

t3_ports = get_service_port_list(svc:'t3');
if (!empty_or_null(t3_ports))
{
  t3_ports = list_uniq(t3_ports);
  foreach port (t3_ports)
  {
    set_kb_item(name:"weblogic/ports", value:port);
    set_kb_item(name:"weblogic/" + port + "/protocols", value:'t3');

    if (empty_or_null(get_kb_item("weblogic/" + port + "/version")))
    {
      # if we didn't get a version via WWW then add the t3 value
      version = get_kb_item("t3/" + port + "/version");

      if (!empty_or_null(version))
      {
        replace_kb_item(name:"weblogic/" + port + "/version", value:version);
        replace_kb_item(name:"weblogic/" + port + "/version_source", value:'t3');
      }
    }
  }
}

# LDAP is kind of weird in that we can't actually tie it back directly to
# WebLogic without using these other installs. So we will just loop through
# the LDAP installs and insert the ones that correlate to an existing web
# logic install
ldap_ports = get_service_port_list(svc:'ldap');
if (!empty_or_null(ldap_ports))
{
  ldap_ports = list_uniq(ldap_ports);
  foreach port (ldap_ports)
  {
    if (!empty_or_null(get_kb_list("weblogic/" + port + "/protocols")))
    {
      set_kb_item(name:"weblogic/" + port + "/protocols", value:'ldap');
    }
  }
}

# loop over our installs and report them
weblogic_ports = get_kb_list("weblogic/ports");
if (empty_or_null(weblogic_ports))
{
  audit(AUDIT_NOT_INST, appname);
}

weblogic_ports = list_uniq(weblogic_ports);
foreach port (weblogic_ports)
{
  info = '';
  version = get_kb_item("weblogic/" + port + "/version");
  if (!empty_or_null(version))
  {
    info += '\nVersion   : ' + version;
    info += '\nSource    : ' + get_kb_item("weblogic/" + port + "/version_source");
  }
  else version = UNKNOWN_VER;

  info += '\nPort      : ' + port;
  info += '\nProtocols : ';
  protocols = get_kb_list("weblogic/" + port + "/protocols");
  foreach protocol (protocols)
  {
    info += protocol;
    info += ' ';
    register_install(app_name:appname, vendor:'Oracle', product:'WebLogic Server', version:version, port:port, cpe:app_cpe, service:protocol);
  }
  info += '\n';
  security_report_v4(severity:SECURITY_NOTE, port:port, extra:info);
}

