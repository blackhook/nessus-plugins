#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73756);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");
  script_xref(name:"IAVA", value:"0001-A-0560");

  script_name(english:"Microsoft SQL Server Unsupported Version Detection (remote check)");

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
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"This version of the software is no longer supported.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mssqlserver_detect.nasl", "ssl_cert_CN_mismatch.nasl");
  script_require_ports(1433, "Services/mssql");

  exit(0);
}

include("spad_log_func.inc");
port = get_service(svc:'mssql', default:1433, exit_on_fail:TRUE);
version = get_kb_item_or_exit("MSSQL/"+port+"/Version");
supported_version = '';

# All Azure-managed versions are currently supported
x509_altNames = get_kb_list(strcat('X509/', port, '/altName'));
foreach var x509_altName (x509_altNames)
  if (x509_altName =~ "database\.windows\.net$" ||
      x509_altName =~ "database\.azure\.com$" ||
      x509_altName =~ "\.sql\.azure")
    exit(0, strcat('The Microsoft Azure SQL Server install listening on port ', port, ' is currently supported.'));

# SQL 2016
if (ver_compare(minver:'13.0', ver:version, fix:'13.0.6300.0', strict:FALSE) == -1) # < SP3
  supported_version = '13.0.6300.2 (2016 SP3)';

# SQL 2014
if (ver_compare(minver:'12.0', ver:version, fix:'12.0.6024.0', strict:FALSE) == -1) # < SP3
  supported_version = '12.0.6024.0 (2014 SP3)';

# Completely unsupported versions
else if (
  # SQL 2012
  version =~ "^11\.0+\." ||
  # SQL 2008
  version =~ "^10\.0+\." ||
  # SQL 2008 R2
  version =~ "^10\.50+\." ||
  # SQL 2005
  version =~ "^9\.0+\." ||
  # SQL 2000
  version =~ "^8\.0+\." ||
  # SQL Server 7.0
  version =~ "^7\.0+\." ||
  # SQL Server 6.5
  version =~ "^6\.50\." ||
  # SQL Server 6.0
  version =~ "^6\.00\."
) supported_version = 'This version is no longer supported.';

if (supported_version)
{
  register_unsupported_product(product_name:"Microsoft SQL Server", version:version,
                               cpe_base:"microsoft:sql_server");

  report =
    '\n' + 'The following unsupported installation of Microsoft SQL Server was' +
    '\n' + 'detected :\n' +
    '\n' +
    '\n' + '  Installed version : ' + version +
    '\n' + '  Fixed version     : ' + supported_version + '\n';


  instance = get_kb_item("MSSQL/" + port + "/InstanceName");
  if(!empty_or_null(instance))
    report += '\n  SQL Server Instance  : ' + instance;

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else exit(0, "The Microsoft SQL Server install listening on port "+port+" is currently supported.");
