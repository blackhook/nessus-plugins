#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80888);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/03");

  script_xref(name:"IAVA", value:"0001-A-0615");

  script_name(english:"Unsupported PAN-OS Operating System");
  script_summary(english:"Checks for EOL.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an obsolete operating system.");
  script_set_attribute(attribute:"description", value:
"According to its version, the remote PAN-OS operating system is
obsolete and is no longer maintained by Palo Alto Networks.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://www.paloaltonetworks.com/services/support/end-of-life-announcements/end-of-life-summary
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee6d34e8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of PAN-OS that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Default unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2023 Tenable Network Security, Inc.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version", "Host/Palo_Alto/Firewall/Model");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

var version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Version");
var full_version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Full_Version");

var latest = '11.0';
var eol = make_array(
# "11.0","2024-11-17",  
# "10.2","2025-08-27", 
# "10.1","2024-12-01",
  "10.0","2022-07-16",
# "9.1", "2023-12-13",
  "9.0", "2022-03-01",
  "8.0", "2019-10-31",
  "7.1", "2020-06-30",
  "7.0", "2017-12-04",
  "6.1", "2018-10-25",
  "6.0", "2017-01-19",
  "5.1", "2017-05-09",
  "5.0", "2016-11-13",
  "4.1", "2015-04-30",
  "4.0", "2014-12-31",
  "3.1", "2013-06-30",
  "3.0", "2010-12-17",
  "2.1", "2012-01-05",
  "2.0", "2009-05-20",
  "1.3", "2008-11-20"
);

var match = pregmatch(string:version, pattern:"^(\d+\.\d+)(?:[^0-9]|$)");
if (isnull(match)) exit(1, 'Error parsing version: ' + version);
var release = match[1];

# versions 0.x - 1.2 aren't listed on Palo Alto Network's EOL page but are presumably unsupported
if (version =~ "^(0\.|1\.[0-2])([^0-9]|$)")
  var eol_date = 'unknown';

## "9.0.0.xfr (VM-Series only)", "2020-08-19"
if (version =~ "^(9\.\d+\.\d+\.xfr$)")
{
  var model = get_kb_item_or_exit('Host/Palo_Alto/Firewall/Model');

  # VM-Series Models (VM-50, VM-100, VM-200, VM-300, VM-500, VM-700, VM-1000-HV
  if (
  model =~ 'VM-50' ||
  model =~ 'VM-100' ||
  model =~ 'VM-200' ||
  model =~ 'VM-300' ||
  model =~ 'VM-500' ||
  model =~ 'VM-700' ||
  model =~ 'VM-1000-HV'
     )
  {
    var eol_date = "2020-09-19";
  }
}
else
  var eol_date = eol[release];

if (isnull(eol_date)) exit(0, 'PAN-OS ' + version + ' is still supported.');

set_kb_item(name:"Host/Palo_Alto/Firewall/unsupported", value:TRUE);

register_unsupported_product(
  product_name: "Palo Alto Networks PAN-OS",
  cpe_class:    CPE_CLASS_OS,
  version:      release,
  cpe_base:     "paloaltonetworks:pan-os"
);

var report =
  '\n  Installed version     : ' + full_version +
  '\n  PAN-OS ' + release + ' EOL date  : ' + eol_date +
  '\n  Latest PAN-OS version : ' + latest +
  '\n  EOL URL               : http://www.nessus.org/u?ee6d34e8' +
  '\n';
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
exit(0);

