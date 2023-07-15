#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71616);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/22");

  script_xref(name:"IAVA", value:"0001-A-0592");

  script_name(english:"Safari Unsupported");
  script_summary(english:"Checks for Safari on Windows");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is no longer
supported.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has an install of Safari, a web browser.

While there has been no formal announcement, Apple appears to have
discontinued support for Safari on Windows and has not released any
updates since version 5.1.7 in May 9, 2012.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Safari_(web_browser)");
  script_set_attribute(attribute:"solution", value:"Remove Safari and install a supported web browser.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2013-2020 Tenable Network Security, Inc.");

  script_dependencies("safari_installed.nasl");
  script_require_keys("SMB/Safari/FileVersion");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

path = get_kb_item_or_exit("SMB/Safari/Path");
ver = get_kb_item("SMB/Safari/FileVersion");
if (isnull(ver)) ver = get_kb_item("SMB/Safari/ProductVersion");
else if (isnull(ver)) ver = "Unknown";

port = get_kb_item("SMB/transport");
if (!port) port = 445;

register_unsupported_product(product_name:"Apple Safari",
                             cpe_base:"apple:safari", version:ver);

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver  +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
