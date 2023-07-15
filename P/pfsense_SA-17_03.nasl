#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106503);
  script_version("1.12");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id(
    "CVE-2016-1889",
    "CVE-2016-6559",
    "CVE-2016-7426",
    "CVE-2016-7427",
    "CVE-2016-7428",
    "CVE-2016-7429",
    "CVE-2016-7431",
    "CVE-2016-7433",
    "CVE-2016-7434",
    "CVE-2016-8610",
    "CVE-2016-8858",
    "CVE-2016-9310",
    "CVE-2016-9311",
    "CVE-2016-9312",
    "CVE-2016-10009",
    "CVE-2016-10010"
  );
  script_bugtraq_id(
    93776,
    93841,
    94444,
    94446,
    94447,
    94448,
    94450,
    94451,
    94452,
    94453,
    94454,
    94455,
    94694,
    94968,
    94972
  );
  script_xref(name:"CERT", value:"633847");
  script_xref(name:"FreeBSD", value:"SA-16:29.bspatch");
  script_xref(name:"FreeBSD", value:"SA-16:31.libarchive");
  script_xref(name:"FreeBSD", value:"SA-16:33.openssh");
  script_xref(name:"FreeBSD", value:"SA-16:35.openssl");
  script_xref(name:"FreeBSD", value:"SA-16:37.libc");
  script_xref(name:"FreeBSD", value:"SA-16:38.bhyve");
  script_xref(name:"FreeBSD", value:"SA-16:39.ntp");
  script_xref(name:"FreeBSD", value:"SA-17:01.openssh");

  script_name(english:"pfSense < 2.3.3 Multiple Vulnerabilities (SA-17_01 - SA-17_03)");
  script_summary(english:"Checks the version of pfSense.");

  script_set_attribute(attribute:"synopsis", value:
"The remote firewall host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote pfSense
install is affected by multiple vulnerabilities as stated in the
referenced vendor advisories.");
  script_set_attribute(attribute:"see_also", value:"https://doc.pfsense.org/index.php/2.3.3_New_Features_and_Changes");
  # https://www.pfsense.org/security/advisories/pfSense-SA-17_01.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96e388ec");
  # https://www.pfsense.org/security/advisories/pfSense-SA-17_02.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?871cf23b");
  # https://www.pfsense.org/security/advisories/pfSense-SA-17_03.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36b6ea9d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to pfSense version 2.3.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6559");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/17");
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
  { "fixed_version" : "2.3.3" }
];

vcf::pfsense::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{xss:TRUE, xsrf:TRUE}
);
