#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121474);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/04");

  script_xref(name:"IAVA", value:"0001-A-0580");

  script_name(english:"pfSense Unsupported Version Detection");
  script_summary(english:"Checks the version of pfSense.");

  script_set_attribute(attribute:"synopsis", value:
"The remote firewall host is an unsupported version of pfSense.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote pfSense
host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://www.netgate.com/docs/pfsense/releases/versions-of-pfsense-and-freebsd.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9a823a02");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of pfSense that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"the product is not longer supported by the vendor");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pfsense:pfsense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bsdperimeter:pfsense");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pfsense_detect.nbin");
  script_require_keys("Host/pfSense");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

if (!get_kb_item("Host/pfSense")) audit(AUDIT_HOST_NOT, "pfSense");

app_info = vcf::pfsense::get_app_info();

constraints = [
  { "fixed_version" : "2.4.5" }
];

vcf::pfsense::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
