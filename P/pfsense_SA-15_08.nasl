#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106497);
  script_version("1.6");
  script_cvs_date("Date: 2018/07/24 18:56:11");

  script_cve_id(
    "CVE-2014-2653",
    "CVE-2015-1283",
    "CVE-2015-1416",
    "CVE-2015-1418",
    "CVE-2015-5600",
    "CVE-2015-5675",
    "CVE-2015-6563",
    "CVE-2015-6564",
    "CVE-2015-6565",
    "CVE-2015-7691",
    "CVE-2015-7692",
    "CVE-2015-7701",
    "CVE-2015-7702",
    "CVE-2015-7703",
    "CVE-2015-7704",
    "CVE-2015-7705",
    "CVE-2015-7803",
    "CVE-2015-7804",
    "CVE-2015-7848",
    "CVE-2015-7849",
    "CVE-2015-7850",
    "CVE-2015-7851",
    "CVE-2015-7852",
    "CVE-2015-7853",
    "CVE-2015-7854",
    "CVE-2015-7855",
    "CVE-2015-7871"
  );
  script_bugtraq_id(
    66459,
    75990,
    76116,
    76236,
    76317,
    76485,
    76497,
    77273,
    77274,
    77275,
    77276,
    77277,
    77278,
    77279,
    77280,
    77281,
    77282,
    77283,
    77284,
    77285,
    77286,
    77287,
    77288
  );
  script_xref(name:"FreeBSD", value:"SA-15:14.bsdpatch");
  script_xref(name:"FreeBSD", value:"SA-15:16.openssh");
  script_xref(name:"FreeBSD", value:"SA-15:18.bsdpatch");
  script_xref(name:"FreeBSD", value:"SA-15:20.expat");
  script_xref(name:"FreeBSD", value:"SA-15:21.amd64");
  script_xref(name:"FreeBSD", value:"SA-15:22.openssh");
  script_xref(name:"FreeBSD", value:"SA-15:25.ntp");
  script_xref(name:"TRA", value:"TRA-2015-04");

  script_name(english:"pfSense < 2.2.5 Multiple Vulnerabilities (SA-15_08)");
  script_summary(english:"Checks the version of pfSense.");

  script_set_attribute(attribute:"synopsis", value:
"The remote firewall host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote pfSense
install is prior to 2.2.5. It is, therefore, affected by multiple
vulnerabilities as stated in the referenced vendor advisories.");
  script_set_attribute(attribute:"see_also", value:"https://doc.pfsense.org/index.php/2.2.5_New_Features_and_Changes");
  # https://www.pfsense.org/security/advisories/pfSense-SA-15_08.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec9ba339");
  script_set_attribute(attribute:"solution", value:
"Upgrade to pfSense version 2.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pfsense:pfsense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bsdperimeter:pfsense");
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
  { "fixed_version" : "2.2.5" }
];

vcf::pfsense::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{xss:TRUE}
);
