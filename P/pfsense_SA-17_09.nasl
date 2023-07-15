#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106506);
  script_version("1.7");
  script_cvs_date("Date: 2018/07/25 14:27:29");

  script_cve_id("CVE-2017-1000479");

  script_name(english:"pfSense 2.3.x < 2.3.5 / 2.4.x < 2.4.2 Multiple XSS Vulnerabilites (SA-17_08 / SA-17_09)");
  script_summary(english:"Checks the version of pfSense.");

  script_set_attribute(attribute:"synopsis", value:
"The remote firewall host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote pfSense
install is 2.3.x prior to 2.3.5 or 2.4.x prior to 2.4.2. It is,
therefore, affected by multiple vulnerabilities as stated in the
referenced vendor advisories.

Note: SA-17_09 only applies to 2.4.x.");
  # https://www.pfsense.org/security/advisories/pfSense-SA-17_08.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?424391cb");
  # https://www.pfsense.org/security/advisories/pfSense-SA-17_09.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?98d3ae56");
  script_set_attribute(attribute:"solution", value:
"Upgrade to pfSense version 2.3.5 / 2.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"metasploit_name", value:'Clickjacking Vulnerability In CSRF Error Page pfSense');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pfsense:pfsense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bsdperimeter:pfsense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

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
  { "min_version" : "2.4.0", "fixed_version" : "2.4.2" },
  { "min_version" : "2.3.0", "fixed_version" : "2.3.5" }
];

vcf::pfsense::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE}
);
