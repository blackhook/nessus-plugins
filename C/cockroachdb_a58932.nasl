#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159484);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id("CVE-2021-3121");

  script_name(english:"CockroachDB 19.2 < 19.2.12 / 20.1 < 20.1.11 / 20.2 < 20.2.4 DoS (A58932)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CockroachDB server is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of CockroachDB installed on the remote host is prior to 19.2.12, 20.1.x prior to 20.1.11, or 20.2.x prior
 to 20.2.4. Therefore, a denial of service (DoS) vulnerability exists in protobuf binary decode functions. An 
 unauthenticated, remote attacker can exploit this issue by sending a specially crafted HTTP request to cause the 
 full-cluster to stop responding.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.cockroachlabs.com/docs/advisories/a58932.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d070cda");
  script_set_attribute(attribute:"solution", value:
"Upgrade to CockroachDB version v19.2.12, v20.1.11, v20.2.4, or a later version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3121");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/02");
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
  {'min_version':'19.2', 'fixed_version':'19.2.12'},
  {'min_version':'20.1', 'fixed_version':'20.1.11'},
  {'min_version':'20.2', 'fixed_version':'20.2.4'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
