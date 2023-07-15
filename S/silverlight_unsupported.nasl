#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58134);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/23");

  script_xref(name:"IAVA", value:"0001-A-0559");

  script_name(english:"Microsoft Silverlight Unsupported Version Detection (Windows)");
  script_summary(english:"Checks version of Microsoft Silverlight");

  script_set_attribute(attribute:"synopsis", value:"The remote host has an unsupported version of Microsoft Silverlight.");
  script_set_attribute(attribute:"description", value:
"The installation of Microsoft Silverlight on
the Windows host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://support.microsoft.com/en-us/windows/silverlight-end-of-support-0a3be3c7-bead-e203-2dfd-74f0a64f1788
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fcc00b67");
  script_set_attribute(attribute:"solution", value:
"Remove Microsoft Silverlight.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Manual analysis of the vulnerability");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2022 Tenable Network Security, Inc.");

  script_dependencies("silverlight_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/Silverlight/Version");

  exit(0);
}


include('global_settings.inc');
include('misc_func.inc');


var kb_base = 'SMB/Silverlight';
var path = get_kb_item_or_exit(kb_base+'/Path');
var version = get_kb_item_or_exit(kb_base+'/Version');

register_unsupported_product(product_name:'Microsoft Silverlight',
                              cpe_base:'microsoft:silverlight', version:version);

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

if (report_verbosity > 0)
{
  var report = 
    '\n  Path               : ' + path +
    '\n  Installed version  : ' + version;
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else security_report_v4(severity:SECURITY_HOLE, port:port);
exit(0);
