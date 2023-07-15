#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(159591);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/07");

  script_name(english:"PCI DSS Compliance : Point-of-Sale (POS) Software Using Default Credentials");

  script_set_attribute(attribute:"synopsis", value:
"A point of sale application is accessible via default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a point of sale application which can be accessed via default credentials. The PCI Data
Security Standard requires default or vendor-shipped credentials to be changed for point-of-sale (PoS) devices.");
  script_set_attribute(attribute:"solution", value:"Change the default credentials according to vendor specifications.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score from an in depth analysis done by Tenable");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mssql_brute_force.nasl");
  script_require_ports("mssql/product_database_port", "Settings/ParanoidReport");
  script_require_keys("Settings/PCI_DSS");
  script_exclude_keys("Settings/PCI_DSS_local_checks");

  exit(0);
}

include("compat_shared.inc");

if (!get_kb_item("Settings/PCI_DSS")) audit(AUDIT_PCI);

if (get_kb_item("Settings/PCI_DSS_local_checks"))
  exit(1, "This plugin only runs for PCI External scans.");

if (report_paranoia < 2) audit(AUDIT_PARANOID);


var products = get_kb_list("PCI/pos_default_creds/*/product");

var username, password, port, report;
foreach var prod (products)
{
  username = get_kb_item("PCI/pos_default_creds/"+prod+"/username");
  password = get_kb_item("PCI/pos_default_creds/"+prod+"/password");
  port = get_kb_item("PCI/pos_default_creds/"+prod+"/port");

  report =
    '\n  Product : ' + prod +
    '\n  Default Username : ' + username +
    '\n  Default Password : ' + password + '\n';

  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}