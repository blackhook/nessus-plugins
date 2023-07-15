#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109947);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-5736", "CVE-2018-5737");

  script_name(english:"ISC BIND 9.12.x < 9.12.1-P1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of BIND.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ISC BIND running on the remote name server is 9.12.x 
prior to 9.12.1-P2. It is, therefore, affected by multiple 
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/docs/aa-01602");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/docs/aa-01606");
  # https://www.us-cert.gov/ncas/current-activity/2018/05/18/ISC-Releases-Security-Advisories-BIND
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1939e95");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ISC BIND version 9.12.1-P2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5737");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

vcf::bind::initialize();

app_info = vcf::get_app_info(app:"BIND", port:53, kb_ver:"bind/version", service:TRUE, proto:"UDP");

constraints = [
  { "min_version" : "9.12.0", "fixed_version" : "9.12.1-P2" },
];
constraints = vcf::bind::filter_constraints(constraints:constraints, version:app_info.version);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
