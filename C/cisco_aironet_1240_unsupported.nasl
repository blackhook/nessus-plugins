#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122370);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/22");

  script_xref(name:"IAVA", value:"0001-A-0526");

  script_name(english:"Cisco Aironet 1240 AG Unsupported Device Detection");
  script_summary(english:"Checks the Cisco device model.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Cisco Aironet 1240 AG host is no longer supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported model number, the remote Cisco
Aironet 1240 AG device is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://www.cisco.com/c/en/us/products/collateral/collaboration-endpoints/unified-ip-phone-7900-series/end_of_life_notice_c51-726425.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f28cdc0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a Cisco Aironet device that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Unsupported / End of Life");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:aironet_ap1240ag");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Platform", "Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "Cisco Aironet 1240 AG";
model = get_kb_item_or_exit("Host/Cisco/IOS/Platform");
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (model != "C1240")
  audit(AUDIT_HOST_NOT, appname);

register_unsupported_product(product_name:appname, cpe_base:"cisco:aironet_ap1240ag", version:version);

report =
  '\n  Model       : ' + appname +
  '\n  IOS version : ' + version +
  '\n  EOL date    : July 26, 2014' +
  '\n  EOL URL     : https://www.cisco.com/c/en/us/products/collateral/collaboration-endpoints/unified-ip-phone-7900-series/end_of_life_notice_c51-726425.html' +
  '\n';

security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
