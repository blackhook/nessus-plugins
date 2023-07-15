#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111790);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-5740");
  script_bugtraq_id(105055);

  script_name(english:"ISC BIND 9.x.x < 9.9.13-P1 / 9.10.x < 9.10.8-P1 / 9.11.x < 9.11.4-P1 / 9.12.x < 9.12.2-P1 deny-answer-aliases DoS Vulnerability");
  script_summary(english:"Checks the version of BIND.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of ISC
BIND running on the remote name server is 9.x.x prior to 9.9.13-P1,
9.10.x prior to 9.10.8-P1, 9.11.x prior to 9.11.4-P1, or 9.12.x prior
to 9.12.2-P1. It is, therefore, affected by a denial of service
vulnerability in the deny-answer-aliases feature.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01639");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ISC BIND version 9.9.13-P1 / 9.10.8-P1 / 9.11.4-P1 /
9.11.3-S3 / 9.12.2-P1 or later. Note that BIND 9 version 9.11.3-S3
is available exclusively for eligible ISC Support customers.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5740");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

vcf::bind::initialize();

app_info = vcf::get_app_info(app:"BIND", port:53, kb_ver:"bind/version", service:TRUE, proto:"UDP");

if (report_paranoia < 2) audit(AUDIT_PARANOID); # patch can be applied

constraints = [
  { "min_version" : "9.7.0", "max_version" : "9.8.8", "fixed_version" : "9.9.13-P1" },
  { "min_version" : "9.9.0", "max_version" : "9.9.13", "fixed_version" : "9.9.13-P1" },
  { "min_version" : "9.10.0", "max_version" : "9.10.8", "fixed_version" : "9.10.8-P1" },
  { "min_version" : "9.11.0", "max_version" : "9.11.4", "fixed_version" : "9.11.4-P1" },
  { "min_version" : "9.9.3-S1", "max_version" : "9.11.3-S2", "fixed_version" : "9.11.3-S3" },
  { "min_version" : "9.12.0", "max_version" : "9.12.2", "fixed_version" : "9.12.2-P1" }
];
constraints = vcf::bind::filter_constraints(constraints:constraints, version:app_info.version);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
