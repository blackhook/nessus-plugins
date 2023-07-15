#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106507);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2017-3737", "CVE-2017-3738");
  script_bugtraq_id(103513);

  script_name(english:"pfSense 2.3.x < 2.3.5-p1 / 2.4.x < 2.4.2-p1 Multiple Vulnerabilities (SA-17_10 / SA-17_11)");
  script_summary(english:"Checks the version of pfSense.");

  script_set_attribute(attribute:"synopsis", value:
"The remote firewall host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote pfSense
install is a version 2.3.x prior to 2.3.5-p1 or 2.4.x prior to
2.4.2-p1. It is, therefore, affected by multiple vulnerabilities.");
  # https://www.pfsense.org/security/advisories/pfSense-SA-17_10.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01bbb779");
  # https://www.pfsense.org/security/advisories/pfSense-SA-17_11.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fcb03f7e");
  # https://www.netgate.com/blog/pfsense-2-4-2-release-p1-and-2-3-5-release-p1-now-available.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26d41513");
  script_set_attribute(attribute:"solution", value:
"Upgrade to pfSense version 2.3.5-p1 / 2.4.2-p1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3738");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pfsense:pfsense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bsdperimeter:pfsense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pfsense_detect.nbin");
  script_require_keys("Host/pfSense");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

if (!get_kb_item("Host/pfSense")) audit(AUDIT_HOST_NOT, "pfSense");

app_info = vcf::pfsense::get_app_info();
constraints = [
  { "min_version" : "2.4.0", "fixed_version" : "2.4.2-p1"},
  { "min_version" : "2.3.0", "fixed_version" : "2.3.5-p1"}
];

vcf::pfsense::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE}
);
