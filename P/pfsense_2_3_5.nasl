#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109037);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/08");

  script_cve_id(
    "CVE-2017-12837",
    "CVE-2017-12883",
    "CVE-2017-13077",
    "CVE-2017-13078",
    "CVE-2017-13079",
    "CVE-2017-13080",
    "CVE-2017-13081",
    "CVE-2017-13082",
    "CVE-2017-13084",
    "CVE-2017-13086",
    "CVE-2017-13087",
    "CVE-2017-13088",
    "CVE-2017-13704",
    "CVE-2017-14491",
    "CVE-2017-14492",
    "CVE-2017-14493",
    "CVE-2017-14494",
    "CVE-2017-14495",
    "CVE-2017-14496"
  );
  script_bugtraq_id(
    100852,
    100860,
    101274,
    103513
  );
  script_xref(name:"IAVA", value:"2017-A-0284-S");
  script_xref(name:"IAVA", value:"2017-A-0310");
  script_xref(name:"FreeBSD", value:"SA-17:07.wpa");

  script_name(english:"pfSense < 2.3.5 Multiple Vulnerabilities (KRACK)");
  script_summary(english:"Checks the version of pfSense.");

  script_set_attribute(attribute:"synopsis", value:
"The remote firewall host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote pfSense
install is affected by multiple vulnerabilities as stated in the
referenced vendor advisories.");
  script_set_attribute(attribute:"see_also", value:"https://doc.pfsense.org/index.php/2.3.5_New_Features_and_Changes");
  # https://www.netgate.com/blog/no-plan-survives-contact-with-the-internet.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee52d9a2");
  # https://www.pfsense.org/security/advisories/pfSense-SA-17_07.packages.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1b23834");
  script_set_attribute(attribute:"see_also", value:"https://www.krackattacks.com/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to pfSense version 2.3.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14493");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pfsense:pfsense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bsdperimeter:pfsense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pfsense_detect.nbin");
  script_require_keys("Host/pfSense");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

if (!get_kb_item("Host/pfSense")) audit(AUDIT_HOST_NOT, "pfSense");

app_info = vcf::pfsense::get_app_info();
constraints = [
  { "fixed_version" : "2.3.5" }
];

vcf::pfsense::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{xss:TRUE}
);
