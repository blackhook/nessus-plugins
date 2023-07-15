#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108516);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id(
    "CVE-2014-3505",
    "CVE-2014-3506",
    "CVE-2014-3507",
    "CVE-2014-3508",
    "CVE-2014-3509",
    "CVE-2014-3510",
    "CVE-2014-3511",
    "CVE-2014-3512",
    "CVE-2014-5139"
  );
  script_bugtraq_id(
    69075,
    69076,
    69077,
    69078,
    69079,
    69081,
    69082,
    69083,
    69084
  );

  script_name(english:"pfSense < 2.1.5 Multiple Vulnerabilities ( SA-14_14 )");
  script_summary(english:"Checks the version of pfSense.");

  script_set_attribute(attribute:"synopsis", value:
"The remote firewall host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote pfSense
install is a version prior to 2.1.5 It is, therefore, affected by 
multiple vulnerabilities.");
  # https://www.pfsense.org/security/advisories/pfSense-SA-14_14.openssl.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f5a6f06");
  script_set_attribute(attribute:"solution", value:
"Upgrade to pfSense version 2.1.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/21");

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
  { "fixed_version" : "2.1.5" }
];

vcf::pfsense::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
