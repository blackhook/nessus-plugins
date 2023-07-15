#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57558);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/22");

  script_xref(name:"IAVA", value:"0001-A-0567");

  script_name(english:"MySQL Unsupported Version Detection");
  script_summary(english:"Checks the version of MySQL.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of a database
server.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of MySQL on the remote host
is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.mysql.com/support/supportedplatforms/database.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mysql.com/support/eol-notice.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to a version of MySQL that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("mysql_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

expdate = make_array(
  '6.0', 'May 22, 2009',
  '5.1', 'December 4, 2013',
  '5.0', 'January 9, 2012',
  '4.1', 'December 31, 2009',
  '4.0', 'December 31, 2008'
);

port = get_service(svc:"mysql", default:3306, exit_on_fail:TRUE);

mysql_init(port:port, exit_on_fail:TRUE);
version = mysql_get_version();
if (isnull(version)) exit(1, "Can't get the version of MySQL listening on port "+port+".");

v = split(version, sep:".", keep:FALSE);
maj = int(v[0]);
min = int(v[1]);
majmin = strcat(int(v[0]), '.', int(v[1]));

if (
  maj < 4 ||
  !isnull(expdate[majmin])
)
{
  register_unsupported_product(product_name:"MySQL Server", version:version,
                              cpe_base:"mysql:mysql");

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version   : ' + version +
      '\n  Supported versions  : 5.5.x / 5.6.x / 5.7.x / 8.0.x';
    if (!isnull(expdate[majmin])) report += '\n  End of support date : ' + expdate[majmin];
    report += '\n';
    datadir = get_kb_item('mysql/' + port + '/datadir');
    if (!empty_or_null(datadir))
    {
      report += '  Data Dir          : ' + datadir + '\n';
    }
    databases = get_kb_item('mysql/' + port + '/databases');
    if (!empty_or_null(databases))
    {
      report += '  Databases         :\n' + databases;
    }

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, 'The MySQL version ' + majmin + ' on port '+port+' is still supported.');
