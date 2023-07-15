#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106505);
  script_version("1.5");
  script_cvs_date("Date: 2018/08/08 12:52:13");


  script_name(english:"pfSense < 2.3.4-p1 Multiple Vulnerabilities (SA-17_05 / SA-17_06)");
  script_summary(english:"Checks the version of pfSense.");

  script_set_attribute(attribute:"synopsis", value:
"The remote firewall host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote pfSense
install is prior to 2.3.4-p1. It is, therefore, affected by multiple
vulnerabilities as stated in the referenced vendor advisories.");
  # https://www.pfsense.org/security/advisories/pfSense-SA-17_05.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f47046e8");
  # https://www.pfsense.org/security/advisories/pfSense-SA-17_06.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9fdd07a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to pfSense version 2.3.4-p1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pfsense:pfsense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bsdperimeter:pfsense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");

  script_dependencies("pfsense_detect.nbin");
  script_require_keys("Host/pfSense");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

if (!get_kb_item("Host/pfSense")) audit(AUDIT_HOST_NOT, "pfSense");

app_info = vcf::pfsense::get_app_info();
constraints = [
  { "fixed_version" : "2.3.4-p1" }
];

vcf::pfsense::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE}
);
