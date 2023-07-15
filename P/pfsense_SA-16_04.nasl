#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106500);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id(
    "CVE-2016-1886",
    "CVE-2016-1887",
    "CVE-2016-2105",
    "CVE-2016-2106",
    "CVE-2016-2107",
    "CVE-2016-2109",
    "CVE-2016-2176"
  );
  script_bugtraq_id(
    87940,
    89744,
    89746,
    89757,
    89760,
    90734
  );
  script_xref(name:"EDB-ID", value:"39768");
  script_xref(name:"EDB-ID", value:"44212");
  script_xref(name:"FreeBSD", value:"SA-16:17.openssl");
  script_xref(name:"FreeBSD", value:"SA-16:18.atkbd");
  script_xref(name:"FreeBSD", value:"SA-16:19.sendmsg");

  script_name(english:"pfSense < 2.3.1 Multiple Vulnerabilities (SA-16_03 / SA-16-04)");
  script_summary(english:"Checks the version of pfSense.");

  script_set_attribute(attribute:"synopsis", value:
"The remote firewall host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote pfSense
install is prior to 2.3.1. It is, therefore, affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://doc.pfsense.org/index.php/2.3.1_New_Features_and_Changes");
  # https://www.pfsense.org/security/advisories/pfSense-SA-16_03.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?434aa389");
  # https://www.pfsense.org/security/advisories/pfSense-SA-16_04.filterlog.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5d9b668");
  script_set_attribute(attribute:"solution", value:
"Upgrade to pfSense version 2.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2109");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pfsense:pfsense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bsdperimeter:pfsense");
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
  { "fixed_version" : "2.3.1"}
];

vcf::pfsense::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{xss:TRUE}
);
