#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106499);
  script_version("1.13");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id(
    "CVE-2015-3197",
    "CVE-2015-5300",
    "CVE-2015-7973",
    "CVE-2015-7974",
    "CVE-2015-7975",
    "CVE-2015-7976",
    "CVE-2015-7977",
    "CVE-2015-7978",
    "CVE-2015-7979",
    "CVE-2015-8138",
    "CVE-2015-8139",
    "CVE-2015-8140",
    "CVE-2015-8158",
    "CVE-2016-0702",
    "CVE-2016-0703",
    "CVE-2016-0704",
    "CVE-2016-0705",
    "CVE-2016-0777",
    "CVE-2016-0778",
    "CVE-2016-0797",
    "CVE-2016-0798",
    "CVE-2016-0799",
    "CVE-2016-0800",
    "CVE-2016-1879",
    "CVE-2016-1882",
    "CVE-2016-1885",
    "CVE-2016-10709"
  );
  script_bugtraq_id(
    77312,
    80695,
    80698,
    80704,
    80754,
    81811,
    81814,
    81815,
    81816,
    81959,
    81960,
    81962,
    81963,
    82102,
    82105,
    82237,
    83705,
    83733,
    83743,
    83754,
    83755,
    83763,
    83764
  );
  script_xref(name:"CERT", value:"583776");
  script_xref(name:"CERT", value:"718152");
  script_xref(name:"EDB-ID", value:"39570");
  script_xref(name:"FreeBSD", value:"SA-16:01.sctp");
  script_xref(name:"FreeBSD", value:"SA-16:02.ntp");
  script_xref(name:"FreeBSD", value:"SA-16:05.tcp");
  script_xref(name:"FreeBSD", value:"SA-16:07.openssh");
  script_xref(name:"FreeBSD", value:"SA-16:09.ntp");
  script_xref(name:"FreeBSD", value:"SA-16:11.openssl");
  script_xref(name:"FreeBSD", value:"SA-16:12.openssl");
  script_xref(name:"FreeBSD", value:"SA-16:15.sysarch");

  script_name(english:"pfSense < 2.3 Multiple Vulnerabilities (SA-16_01 - SA-16_02)");
  script_summary(english:"Checks the version of pfSense.");

  script_set_attribute(attribute:"synopsis", value:
"The remote firewall host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote pfSense
install is prior to 2.3. It is, therefore, affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://doc.pfsense.org/index.php/2.3_New_Features_and_Changes");
  # https://www.pfsense.org/security/advisories/pfSense-SA-16_01.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b03b53c4");
  # https://www.pfsense.org/security/advisories/pfSense-SA-16_02.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b296df96");
  script_set_attribute(attribute:"solution", value:
"Upgrade to pfSense version 2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0799");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'pfSense authenticated graph status RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/01");
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
  { "fixed_version" : "2.3"}
];

vcf::pfsense::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{xss:TRUE}
);
