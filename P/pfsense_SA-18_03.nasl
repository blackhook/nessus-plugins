#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109038);
  script_version("1.4");
  script_cvs_date("Date: 2018/07/25 14:27:29");

  script_cve_id("CVE-2017-5715", "CVE-2017-5754", "CVE-2018-6916");
  script_bugtraq_id(103513);
  script_xref(name:"FreeBSD", value:"SA-18:01.ipsec");
  script_xref(name:"FreeBSD", value:"SA-18:03.speculative_execution");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"pfSense < 2.4.3 Multiple Vulnerabilities (SA-18_01 / SA-18_02 / SA-18_03) (Meltdown) (Spectre)");
  script_summary(english:"Checks the version of pfSense.");

  script_set_attribute(attribute:"synopsis", value:
"The remote firewall host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote pfSense
install is a version prior to 2.4.3 It is, therefore, affected by 
multiple vulnerabilities as stated in the referenced vendor
advisories.");
  script_set_attribute(attribute:"see_also", value:"https://doc.pfsense.org/index.php/2.4.3_New_Features_and_Changes");
  # https://www.pfsense.org/security/advisories/pfSense-SA-18_01.packages.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ac779c2");
  # https://www.pfsense.org/security/advisories/pfSense-SA-18_02.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d531aa61");
  # https://www.pfsense.org/security/advisories/pfSense-SA-18_03.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c483bc2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to pfSense version 2.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pfsense:pfsense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bsdperimeter:pfsense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pfsense_detect.nbin");
  script_require_keys("Host/pfSense");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

if (!get_kb_item("Host/pfSense")) audit(AUDIT_HOST_NOT, "pfSense");

app_info = vcf::pfsense::get_app_info();
constraints = [
  { "fixed_version" : "2.4.3" }
];

vcf::pfsense::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{xss:TRUE, xsrf:TRUE}
);
