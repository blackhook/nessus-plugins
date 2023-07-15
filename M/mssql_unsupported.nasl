#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64784);
  script_version("1.29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");
  script_xref(name:"IAVA", value:"0001-A-0560");

  script_name(english:"Microsoft SQL Server Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of a database server is running on the remote
host.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Microsoft SQL Server on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=SQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4418a57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Microsoft SQL Server that is currently
supported.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"This version of the software is no longer supported.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mssql_version.nasl");
  script_require_keys("mssql/installed");
  script_require_ports(139, 445);

  exit(0);
}

include('spad_log_func.inc');

function get_install_text(version, verbose_version, path, instance_name, sqltype, supported_version)
{
  local_var res;
  if(isnull(version) || isnull(supported_version))
    exit(1, 'Missing argument to get_install_text()');
  res =  '\n  Installed version         : ' + version;
  if (!isnull(verbose_version)) res += ' (' + verbose_version + ')';
  if (!isnull(sqltype)) res += ' ' + sqltype;
  if(!empty_or_null(path))
    res += '\n  Install path              : ' + path;
  if(!isnull(instance_name))
    res += '\n  Instance                  : ' + instance_name;
  res += '\n  Minimum supported version : ' + supported_version + '\n';
  return res;
}

var port = get_kb_item("SMB/transport");
if (!port) port = 445;

var ver_list = get_kb_list_or_exit("mssql/installs/*/SQLVersion");
var info = '';

foreach var item (keys(ver_list))
{
  item -= 'mssql/installs/';
  item -= '/SQLVersion';
  var path = item;

  var version = get_kb_item_or_exit("mssql/installs/" + path + "/SQLVersion");

  var verbose_version = get_kb_item("mssql/installs/" + path + "/SQLVerboseVersion");

  var sqltype = get_kb_item("mssql/installs/" + path + "/edition_type");
  if (isnull(sqltype)) sqltype = get_kb_item("mssql/installs/" + path + "/edition");

  var instance = get_kb_item("mssql/installs/" + path + "/NamedInstance");

  # Windows Internal Database - Don't report as its covered by OS updates
  if ("Windows Internal Database" >< sqltype)
  {
    spad_log(message:'Windows Internal Database encountered.  Skipping.\n');
    continue;
  }

  # Windows SQL Server LocalDB - Don't report
  if ("LOCALDB" >< instance)
  {
    spad_log(message:'LocalDB encountered.  Skipping.\n');
    continue;
  }

   # SQL 2016
  if (ver_compare(minver:'13.0', ver:version, fix:'13.0.6300.2', strict:FALSE) == -1 ) # < SP3
  {
    register_unsupported_product(product_name:"Microsoft SQL Server", version:version,
                                 cpe_base:"microsoft:sql_server");
    info += get_install_text(version: version, verbose_version: verbose_version, path:path,
                             sqltype: sqltype, supported_version: "13.0.6300.2 (2016 SP3)",
                             instance_name: instance);
  }

  # SQL 2014
  else if (ver_compare(minver:'12.0', ver:version, fix:'12.0.6024.0', strict:FALSE) == -1 ) # < SP3
  {
    register_unsupported_product(product_name:"Microsoft SQL Server", version:version,
                                 cpe_base:"microsoft:sql_server");
    info += get_install_text(version: version, verbose_version: verbose_version, path:path,
                             sqltype: sqltype, supported_version: "12.0.6024.0 (2014 SP3)",
                             instance_name: instance);
  }

  # Completely unsupported SQL Servers versions
  else if (
    # SQL 2012
    version =~ "^11\.0\." ||
    # SQL 2008 R2
    version =~ "^10\.50\." ||
    # SQL 2008
    version =~ "^10\.0\." ||
    # SQL 2005
    version =~ "^9\.00\." ||
    # SQL 2000
    version =~ "^8\.00\." ||
    # SQL Server 7.0
    version =~ "^7\.00\." ||
    # SQL Server 6.5
    version =~ "^6\.50\." ||
    # SQL Server 6.0
    version =~ "^6\.00\."
  )
  {
    register_unsupported_product(product_name:"Microsoft SQL Server", version:version,
                                 cpe_base:"microsoft:sql_server");

    info += get_install_text(version: version, verbose_version: verbose_version, path:path,
                             sqltype: sqltype, supported_version: "This version is no longer supported.",
                             instance_name: instance);
  }
}

var  report = NULL;

if (info != '')
{
  report = '\n' + 'The following unsupported installations of Microsoft SQL Server were' +
           '\n' + 'detected :\n' +
           info;
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_NOT_INST, "An unsupported version of Microsoft SQL Server");
