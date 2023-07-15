#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58092);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_xref(name:"IAVA", value:"0001-A-0559");

  script_name(english:"Microsoft Silverlight Unsupported Version Detection (Mac OS X)");
  script_summary(english:"Checks version of Microsoft Silverlight");

  script_set_attribute(attribute:"synopsis", value:"The remote host has an unsupported version of Microsoft Silverlight.");
  script_set_attribute(attribute:"description", value:
"The installation of Microsoft Silverlight on
the Mac OS X host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/gp/lifean45");
  script_set_attribute(attribute:"solution", value:
"Remove Microsoft Silverlight.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2022 Tenable Network Security, Inc.");

  script_dependencies("macosx_silverlight_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Silverlight/Installed");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


kb_base = "MacOSX/Silverlight";
get_kb_item_or_exit(kb_base+"/Installed");
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);

register_unsupported_product(product_name:"Microsoft Silverlight",
                              cpe_base:"microsoft:silverlight", version:version);

if (report_verbosity > 0)
{
  report = strcat(
    '\n  Path              : ', path,
    '\n  Installed version : ', version);
  security_hole(port:0, extra:report);
}
else security_hole(0);
exit(0);
