#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106490);
  script_version("1.5");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id(
    "CVE-2014-4687",
    "CVE-2014-4688",
    "CVE-2014-4689",
    "CVE-2014-4690",
    "CVE-2014-4691",
    "CVE-2014-4692"
  );
  script_bugtraq_id(
    77960,
    77966,
    77967,
    77978,
    77982,
    80084
  );

  script_name(english:"pfSense < 2.1.4 Multiple Vulnerabilities (SA-14_08 - SA-14_12)");
  script_summary(english:"Checks the version of pfSense.");

  script_set_attribute(attribute:"synopsis", value:
"The remote firewall host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote pfSense
install is prior to 2.1.4. It is, therefore, affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.pfsense.org/security/advisories/pfSense-SA-14_12.webgui.asc");
  script_set_attribute(attribute:"see_also", value:"https://www.pfsense.org/security/advisories/pfSense-SA-14_11.webgui.asc");
  script_set_attribute(attribute:"see_also", value:"https://www.pfsense.org/security/advisories/pfSense-SA-14_10.webgui.asc");
  script_set_attribute(attribute:"see_also", value:"https://www.pfsense.org/security/advisories/pfSense-SA-14_09.webgui.asc");
  script_set_attribute(attribute:"see_also", value:"https://www.pfsense.org/security/advisories/pfSense-SA-14_08.webgui.asc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to pfSense version 2.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-4691");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pfsense:pfsense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bsdperimeter:pfsense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

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
  { "fixed_version" : "2.1.4" }
];

vcf::pfsense::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE}
);
