#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10719); 
 script_version("1.44");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_xref(name:"IAVT", value:"0001-T-0802");

 script_name(english:"MySQL Server Detection");
 script_summary(english:"MySQL Server detection");

 script_set_attribute(attribute:"synopsis", value:
"A database server is listening on the remote port.");
 script_set_attribute(attribute:"description", value:
"The remote host is running MySQL, an open source database server.");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/08/13");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
 script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Databases");

 script_require_ports("Services/mysql", 3306);
 script_dependencies("dbms_injection_detect.nbin", "mysql_unpassworded.nasl");
 exit(0);
}

include('install_func.inc');
include('mysql_func.inc');
include('debug.inc');

var app = 'MySQL Server';
var service = 'mysql';
var cpe = 'cpe:/a:mysql:mysql';
var maria_cpe = 'cpe:/a:mariadb:mariadb';
var extras = make_array('Detection', 'Remote');
var sqlvar, report, match, maria_version;

var port = get_service(svc:"mysql", default:3306, exit_on_fail:TRUE);

var version = get_mysql_version(port:port);
if(version)
{
  report =
    '\nVersion  : ' + version ;
  report += '\n\nNOTE: This information was gathered through a SQL injection.';

  sqlvar = mysql_get_variant();

  if (!empty_or_null(sqlvar))
  {
    extras['Variant'] = sqlvar;
    if (sqlvar == 'MariaDB')
    {
      dbg::detailed_log(lvl:1, msg:'MariaDB version before parsing: ' + obj_rep(version));
      match = pregmatch(pattern:"^5\.5\.5-([0-9]+\.[0-9]+\.[0-9]+)-MariaDB", string:version);
      if (!isnull(match)) maria_version = match[1];
      register_install(
        app_name        : sqlvar,
        vendor : 'MariaDB',
        product : 'MariaDB',
        version         : maria_version,
        port            : port,
        service         : service,
        cpe             : maria_cpe
      );
    }
  }

  register_install(
    app_name        : app,
    vendor : 'MySQL',
    product : 'MySQL',
    version         : version,
    port            : port,
    service         : service,
    extra_no_report : extras,
    cpe             : cpe
  );

  security_note(port:port, extra:report);
  exit(0);
}

function str_status()
{
  local_var status, statuses, str_status;
  status = _FCT_ANON_ARGS[0];
  statuses = make_list();

  if (isnull(status)) return NULL;

  if (status & SERVER_STATUS_IN_TRANS) statuses = make_list(statuses, 'SERVER_STATUS_IN_TRANS');
  if (status & SERVER_STATUS_AUTOCOMMIT) statuses = make_list(statuses, 'SERVER_STATUS_AUTOCOMMIT');
  if (status & SERVER_MORE_RESULTS_EXISTS) statuses = make_list(statuses, 'SERVER_MORE_RESULTS_EXISTS');
  if (status & SERVER_QUERY_NO_GOOD_INDEX_USED) statuses = make_list(statuses, 'SERVER_QUERY_NO_GOOD_INDEX_USED');
  if (status & SERVER_QUERY_NO_INDEX_USED) statuses = make_list(statuses, ' SERVER_QUERY_NO_INDEX_USED');
  if (status & SERVER_STATUS_CURSOR_EXISTS) statuses = make_list(statuses, 'SERVER_STATUS_CURSOR_EXISTS');
  if (status & SERVER_STATUS_LAST_ROW_SENT) statuses = make_list(statuses, 'SERVER_STATUS_LAST_ROW_SENT');
  if (status & SERVER_STATUS_DB_DROPPED) statuses = make_list(statuses, 'SERVER_STATUS_DB_DROPPED');
  if (status & SERVER_STATUS_NO_BACKSLASH_ESCAPES) statuses = make_list(statuses, 'SERVER_STATUS_NO_BACKSLASH_ESCAPES');
  if (status & SERVER_STATUS_METADATA_CHANGED) statuses = make_list(statuses, 'SERVER_STATUS_METADATA_CHANGED');
  if (status & SERVER_QUERY_WAS_SLOW) statuses = make_list(statuses, 'SERVER_QUERY_WAS_SLOW');
  if (status & SERVER_PS_OUT_PARAMS) statuses = make_list(statuses, 'SERVER_PS_OUT_PARAMS');

  if (max_index(statuses) == 0) return NULL;
  else return join(statuses, sep:', ');
}

function str_caps()
{
  local_var caps, str_caps;
  caps = _FCT_ANON_ARGS[0];
  str_caps = NULL;

  if (isnull(caps)) return NULL;

  if (caps & CLIENT_LONG_PASSWORD) str_caps += '\n  CLIENT_LONG_PASSWORD (new more secure passwords)';
  if (caps & CLIENT_FOUND_ROWS) str_caps += '\n  CLIENT_FOUND_ROWS (Found instead of affected rows)';
  if (caps & CLIENT_LONG_FLAG) str_caps += '\n  CLIENT_LONG_FLAG (Get all column flags)';
  if (caps & CLIENT_CONNECT_WITH_DB) str_caps += '\n  CLIENT_CONNECT_WITH_DB (One can specify db on connect)';
  if (caps & CLIENT_NO_SCHEMA) str_caps += '\n  CLIENT_NO_SCHEMA (Don\'t allow database.table.column)';
  if (caps & CLIENT_COMPRESS) str_caps += '\n  CLIENT_COMPRESS (Can use compression protocol)';
  if (caps & CLIENT_ODBC) str_caps += '\n  CLIENT_ODBC (ODBC client)';
  if (caps & CLIENT_LOCAL_FILES) str_caps += '\n  CLIENT_LOCAL_FILES (Can use LOAD DATA LOCAL)';
  if (caps & CLIENT_IGNORE_SPACE) str_caps += '\n  CLIENT_IGNORE_SPACE (Ignore spaces before "(")';
  if (caps & CLIENT_PROTOCOL_41) str_caps += '\n  CLIENT_PROTOCOL_41 (New 4.1 protocol)';
  if (caps & CLIENT_INTERACTIVE) str_caps += '\n  CLIENT_INTERACTIVE (This is an interactive client)';
  if (caps & CLIENT_SSL) str_caps += '\n  CLIENT_SSL (Switch to SSL after handshake)';
  if (caps & CLIENT_IGNORE_SIGPIPE) str_caps += '\n  CLIENT_SIGPIPE (IGNORE sigpipes)';
  if (caps & CLIENT_TRANSACTIONS) str_caps += '\n  CLIENT_TRANSACTIONS (Client knows about transactions)';
  if (caps & CLIENT_RESERVED) str_caps += '\n  CLIENT_RESERVED (Old flag for 4.1 protocol)';
  if (caps & CLIENT_SECURE_CONNECTION) str_caps += '\n  CLIENT_SECURE_CONNECTION (New 4.1 authentication)';
  if (caps & CLIENT_MULTI_STATEMENTS) str_caps += '\n  CLIENT_MULTI_STATEMENTS (Enable/disable multi-stmt support)';
  if (caps & CLIENT_MULTI_RESULTS) str_caps += '\n  CLIENT_MULTI_RESULTS (Enable/disable multi-results)';
  if (caps & CLIENT_PS_MULTI_RESULTS) str_caps += '\n  CLIENT_PS_MULTI_RESULTS (Multi-results in PS-protocol)';
  if (caps & CLIENT_SSL_VERIFY_SERVER_CERT) str_caps += '\n  CLIENT_SSL_VERIFY_SERVER_CERT';
  if (caps & CLIENT_REMEMBER_OPTIONS) str_caps += '\n  CLIENT_REMEMBER_OPTIONS';

  return str_caps;
}

if (mysql_init(port:port) == 1)
{
  if (mysql_get_protocol() == 10)
  {
   version = mysql_get_version();
   set_mysql_version (port:port, version:version);  # used by GPL plugins
   sqlvar = mysql_get_variant();
   str_status = str_status(mysql_get_status());
   caps = mysql_get_caps();
   str_caps = str_caps(mysql_get_caps());

   if (get_kb_item("Settings/PCI_DSS") && !isnull(caps) && !(caps & CLIENT_SSL))
   {
     set_kb_item(name:"PCI/ClearTextCreds/" + port, value:"The remote MySQL server accepts cleartext logins.");
   }

   report =
     '\nVersion  : ' + version +
     '\nProtocol : ' + mysql_get_protocol();
   if (!isnull(str_status)) report += '\nServer Status : ' + str_status;
   if (!isnull(str_caps)) report += '\nServer Capabilities : ' +str_caps;
   report += '\n';

   security_note(port:port, extra:report);
   register_service(port:port, proto:"mysql");
  }
}
else
{
  err = mysql_get_last_error();
  if ('is not allowed to connect to this MySQL server' >< err['msg'])
  {
    security_note(port:port, extra:"
The remote database access is restricted and configured to reject access
from unauthorized IPs.  Therefore it was not possible to extract its
version number."
    );
    register_service(port:port, proto:"mysql");
  }

  if (isnull(err))
  {
    # this is expected when the mysql_init() doesn't even get a valid mysql response from the server
    # ie if the port is closed or mysql isn't running on the port
    mysql_close();
    audit(AUDIT_NOT_DETECT, 'mysql', port);
  }
}
mysql_close();

if (!empty_or_null(sqlvar))
{
  extras['Variant'] = sqlvar;
  if (sqlvar == 'MariaDB')
  {
    variant_cpe = 'cpe:/a:mariadb:mariadb';
    dbg::detailed_log(lvl:1, msg:'MariaDB version before parsing: ' + obj_rep(version));
    match = pregmatch(pattern:"^5\.5\.5-([0-9]+\.[0-9]+\.[0-9]+)-MariaDB", string:version);
    if (!empty_or_null(match)) maria_version = match[1];

    register_install(
      app_name        : sqlvar,
      vendor : 'MariaDB',
      product : 'MariaDB',
      version         : maria_version,
      port            : port,
      service         : service,
      cpe             : maria_cpe
    );
  }
}

register_install(
  app_name        : app,
  vendor : 'MySQL',
  product : 'MySQL',
  version         : version,
  port            : port,
  service         : service,
  extra_no_report : extras,
  cpe             : cpe
);

