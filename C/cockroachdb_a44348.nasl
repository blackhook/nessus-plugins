#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159480);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/04");
  script_xref(name:"CWE", value:"CWE-200");

  script_name(english:"CockroachDB < 2.1.12 / 19.x < 19.1.8 / 19.2 < 19.2.4 Information Disclosure (A44348)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CockroachDB server is affected by a information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of CockroachDB installed on the remote host has a privileged HTTP endpoint which is incorrectly available 
to non-admin users. An unauthenticated, remote attacker can exploit this issue by sending a specially crafted HTTP 
request to obtain sensitive information from the remote cliuser.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.cockroachlabs.com/docs/advisories/a44348
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d7b2446");
  script_set_attribute(attribute:"solution", value:
"Upgrade to CockroachDB version 2.1.12, 19.1.8, 19.2.4, or a later version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute: "cvss_score_source", value: "manual");
  script_set_attribute(attribute: "cvss_score_rationale", value: "Information Disclosure");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cockroach_labs:cockroachdb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cockroachdb_web_console_detect.nbin");
  script_require_keys("installed_sw/CockroachDB");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info, constraints;

app_info = vcf::cockroachdb::get_app_info();

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {'fixed_version':'2.1.12'},
  {'min_version':'19.1', 'fixed_version':'19.1.8'},
  {'min_version':'19.2', 'fixed_version':'19.2.4'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);