#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104574);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/04");

  script_cve_id("CVE-2017-12172", "CVE-2017-15098", "CVE-2017-15099");

  script_name(english:"PostgreSQL 9.2.x < 9.2.24 / 9.3.x < 9.3.20 / 9.4.x < 9.4.15 / 9.5.x < 9.5.10 / 9.6.x < 9.6.6 / 10.x < 10.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 9.2.x prior
to 9.2.24, 9.3.x prior to 9.3.20, 9.4.x prior to 9.4.15, 9.5.x prior
to 9.5.10, 9.6.x prior to 9.6.6, or 10.x prior to 10.1. It is,
therefore, affected by multiple vulnerabilities including a denial of
service attack.");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/about/news/1801/");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/current/release-9-2-24.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/current/release-9-3-20.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/current/release-9-4-15.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/current/release-9-5-10.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/current/release-9-6-6.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/current/release-10-1.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL version 9.2.24 / 9.3.20 / 9.4.15 / 9.5.10 /
9.6.6 / 10.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12172");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("postgres_installed_windows.nbin", "postgres_installed_nix.nbin", "postgresql_version.nbin");
  script_require_ports("Services/postgresql", 5432, "installed_sw/PostgreSQL");

  exit(0);
}

include('vcf_extras_postgresql.inc');

var app = 'PostgreSQL';
var win_local = TRUE;

if (!get_kb_item('SMB/Registry/Enumerated'))
  win_local = FALSE;

var port = get_service(svc:'postgresql', default:5432);
var kb_base = 'database/' + port + '/postgresql/';
var kb_ver = NULL;
var kb_path = kb_base + 'version';
var ver = get_kb_item(kb_path);
if (!empty_or_null(ver)) kb_ver = kb_path;

app_info = vcf::postgresql::get_app_info(app:app, port:port, kb_ver:kb_ver, kb_base:kb_base, win_local:win_local);
vcf::check_granularity(app_info:app_info, sig_segments:2);

#  9.2.24 / 9.3.20 / 9.4.15 / 9.5.10 / 9.6.6 / 10.1
constraints = [
  { "min_version" : "9.2", "fixed_version" : "9.2.24" },
  { "min_version" : "9.3", "fixed_version" : "9.3.20" },
  { "min_version" : "9.4", "fixed_version" : "9.4.15" },
  { "min_version" : "9.5", "fixed_version" : "9.5.10" },
  { "min_version" : "9.6", "fixed_version" : "9.6.6" },
  { "min_version" : "10.0", "fixed_version" : "10.1" }
];

vcf::postgresql::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
