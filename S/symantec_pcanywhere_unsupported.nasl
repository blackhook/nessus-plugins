#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(57859);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_xref(name:"IAVA", value:"0001-A-0601");

  script_name(english:"Symantec pcAnywhere Unsupported");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported remote access application is running or installed on
the remote host.");
  script_set_attribute(attribute:"description", value:
"The installation of Symantec pcAnywhere running or installed on the
remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/en_US/article.HOWTO98455.html");
  script_set_attribute(attribute:"see_also", value:"https://www.symantec.com/connect/blogs/pcanywhere-eol");
  # https://support.symantec.com/content/unifiedweb/en_US/product.pcanywhere.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ed9faa9");
  script_set_attribute(attribute:"solution", value:
"Remove Symantec pcAnywhere.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:pcanywhere");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("PC_anywhere_tcp.nasl", "PC_anywhere.nasl", "symantec_pcanywhere_installed.nasl");
  script_require_ports("Services/pcanywheredata", "SMB/Symantec pcAnywhere/Path", "SMB/Symantec pcAnywhere/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = NULL;
report  = NULL;

# Check for listening
port = get_service(svc:"pcanywheredata", exit_on_fail:FALSE);
if (!port)
{
  # Check for installation locally if not found listening
  path = get_kb_item('SMB/Symantec pcAnywhere/Path');
  if (empty_or_null(path)) audit(AUDIT_NOT_INST, "Symantec pcAnywhere");

  version = get_kb_item('SMB/Symantec pcAnywhere/Version');
  
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  report = '\n  Path                 : ' + path;
}
else
  report = '\n  Port                 : ' + port;

if (empty_or_null(version))
  version = "unknown";

register_unsupported_product(product_name:"Symantec pcAnywhere",
                               cpe_base:"symantec:pcanywhere", version:version);

report +=
  '\n  Installed version    : ' + version +
  '\n  EOL date             : 2015/11/03' +
  '\n  EOL URL              : https://www.symantec.com/connect/blogs/pcanywhere-eol' +
  '\n';

security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
