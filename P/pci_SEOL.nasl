#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include("compat.inc");

if (description)
{
  script_id(176329);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"PCI DSS Compliance : Security End of Life Software");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of software is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, the following software is no longer maintained by its vendor or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.

The PCI Data Security Standard requires remediation of outdated technologies, including those for which vendors have
announced 'end of life' plans.");
  script_set_attribute(attribute:"solution", value:"Upgrade to a version of software that is currently supported.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Settings/PCI_DSS", "NumUnsupportedProducts");

  exit(0);
}

include("compat_shared.inc");

if (!get_kb_item("Settings/PCI_DSS")) audit(AUDIT_PCI);

var numProducts = get_kb_item_or_exit("NumUnsupportedProducts");

var report ='';

for (var i =0; i < numProducts; i++)
{
  report += '\n';
  report += '  Product : ' + get_kb_item("UnsupportedProducts/" + i + "/product_name") + '\n';
  report += '  Version : ' + get_kb_item("UnsupportedProducts/" + i + "/version") + '\n';
  report += '\n';
}

security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
