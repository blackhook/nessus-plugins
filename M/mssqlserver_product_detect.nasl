#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(108409);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Microsoft SQL Server TCP/IP Listener Product Database Detection");

  script_set_attribute(attribute:"synopsis", value:
"A database server for a product is listening on the remote port.");
  script_set_attribute(attribute:"description", value:
"The remote host is running an MSSQL database with default credentials.
It may be possible to determine the product associated with the
database based on the default credentials.");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mssql_brute_force.nasl");
  script_require_ports("mssql/product_database_port", "Settings/ParanoidReport");

  exit(0);
}

include("compat_shared.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var port = get_kb_item_or_exit("mssql/product_database_port");
var prod = get_kb_item_or_exit("mssql/"+port+"/database/product");

var pos_products = [
  "PC America Restaurant Pro Express / Cash Register Express",
  "PC America Restaurant Pro Express"
];

foreach var pos_product (pos_products)
{
  if (prod == pos_product)
    set_kb_item(name:"PCI/POS/"+port, value:prod);
}

var url = get_kb_item("mssql/"+port+"/database/product_link");

var report = 
  '\n  Product : ' + prod;

if (!empty_or_null(url))
  report += '\n  URL     : ' + url;

report +=
  '\n';

security_report_v4(severity:SECURITY_NOTE,port:port, extra:report);
