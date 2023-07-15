#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106498);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id(
    "CVE-2015-3194",
    "CVE-2015-3195",
    "CVE-2015-3196",
    "CVE-2015-8023"
  );
  script_bugtraq_id(
    78622,
    78623,
    78626,
    84947
  );
  script_xref(name:"FreeBSD", value:"SA-15:26.openssl");

  script_name(english:"pfSense < 2.2.6 Multiple Vulnerabilities (SA-15_09 / SA-15_10 / SA-15_11)");
  script_summary(english:"Checks the version of pfSense.");

  script_set_attribute(attribute:"synopsis", value:
"The remote firewall host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote pfSense
install is prior to 2.2.6. It is, therefore, affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://doc.pfsense.org/index.php/2.2.6_New_Features_and_Changes");
  # https://www.pfsense.org/security/advisories/pfSense-SA-15_09.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05b5b916");
  # https://www.pfsense.org/security/advisories/pfSense-SA-15_10.captiveportal.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cecc787a");
  # https://www.pfsense.org/security/advisories/pfSense-SA-15_11.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?354b97b7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to pfSense version 2.2.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8023");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/21");
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
  { "fixed_version" : "2.2.6" }
];

vcf::pfsense::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE, xsrf:TRUE, sqli:TRUE}
);
