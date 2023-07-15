#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106488);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id(
    "CVE-2013-4353",
    "CVE-2013-5211",
    "CVE-2013-6449",
    "CVE-2013-6450",
    "CVE-2014-1452"
  );
  script_bugtraq_id(
    64530,
    64618,
    64691,
    64692,
    64967
  );
  script_xref(name:"FreeBSD", value:"SA-14:01.bsnmpd");
  script_xref(name:"FreeBSD", value:"SA-14:02.ntpd");
  script_xref(name:"FreeBSD", value:"SA-14:03.openssl");

  script_name(english:"pfSense < 2.1.1 Multiple Vulnerabilities (SA-14_02 / SA-14_03)");
  script_summary(english:"Checks the version of pfSense.");

  script_set_attribute(attribute:"synopsis", value:
"The remote firewall host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote pfSense
install is prior to 2.1.1. It is, therefore, affected by multiple
vulnerabilities as stated in the referenced vendor advisories.");
  script_set_attribute(attribute:"see_also", value:"https://doc.pfsense.org/index.php/2.1.1_New_Features_and_Changes");
  # https://www.pfsense.org/security/advisories/pfSense-SA-14_02.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df2891d0");
  # https://www.pfsense.org/security/advisories/pfSense-SA-14_03.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?780104d5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to pfSense version 2.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1452");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/04");
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
  { "fixed_version" : "2.1.1" }
];

vcf::pfsense::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE}
);
