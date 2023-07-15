#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135204);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-14721");
  script_bugtraq_id(109276);

  script_name(english:"Oracle NoSQL Database Enterprise Server-Side Request Forgery (October 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A database running on the remote host is affected by a server-side request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle NoSQL Database Enterprise running on the remote host is prior to 19.3.12. It is, therefore,
affected by a server-side request forgery vulnerability. The vulnerability exists in the jackson-databind component due
to a failure to block the axis2-jaxws class from polymorphic deserialization. An unauthenticated, remote attacker can
exploit this, via HTTP, to cause a takeover of Oracle NoSQL Database.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2019.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle NoSQL Database Enterprise version 19.3.12 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14721");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:oracle:nosql_database");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_nosql_nix_installed.nbin");
  script_require_keys("installed_sw/Oracle NoSQL Database");

  exit(0);
}

include('vcf.inc');

app = vcf::get_app_info(app:'Oracle NoSQL Database');

if (empty_or_null(app['Edition']) || app['Edition'] != 'Enterprise')
  audit(AUDIT_HOST_NOT, 'Oracle NoSQL Database Enterprise');

constraints =
[
  {'fixed_version' : '19.3.12'}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE, strict:FALSE);
