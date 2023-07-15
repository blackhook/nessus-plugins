#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106504);
  script_version("1.10");
  script_cvs_date("Date: 2019/02/26  4:50:08");

  script_cve_id(
    "CVE-2016-9042",
    "CVE-2016-10195",
    "CVE-2016-10196",
    "CVE-2016-10197",
    "CVE-2017-6462",
    "CVE-2017-6463",
    "CVE-2017-6464",
    "CVE-2017-7407",
    "CVE-2017-7468"
  );
  script_bugtraq_id(96014, 97045, 97046, 97049, 97050);

  script_name(english:"pfSense < 2.3.4 Multiple Vulnerabilities (SA-17_04)");
  script_summary(english:"Checks the version of pfSense.");

  script_set_attribute(attribute:"synopsis", value:
"The remote firewall host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote pfSense
install is affected by multiple vulnerabilities as stated in the
referenced vendor advisories.");
  script_set_attribute(attribute:"see_also", value:"https://doc.pfsense.org/index.php/2.3.4_New_Features_and_Changes");
  # https://www.pfsense.org/security/advisories/pfSense-SA-17_04.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9040c63f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to pfSense version 2.3.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-10195");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/26");
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
  { "fixed_version" : "2.3.4" }
];

vcf::pfsense::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{xss:TRUE}
);
