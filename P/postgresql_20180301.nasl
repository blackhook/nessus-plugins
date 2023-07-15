#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(107226);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/04");

  script_cve_id("CVE-2018-1058");
  script_bugtraq_id(103221);

  script_name(english:"PostgreSQL 9.3.x < 9.3.22 / 9.4.x < 9.4.17 / 9.5.x < 9.5.12 / 9.6.x < 9.6.8 / 10.x < 10.3 Privilege Escalation Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 9.3.x prior
to 9.3.22, 9.4.x prior to 9.4.17, 9.5.x prior to 9.5.12, 9.6.x prior
to 9.6.8, or 10.x prior to 10.3. It is, therefore, affected by a
privilege escalation vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/about/news/1834/");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/current/release-9-3-22.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/current/release-9-4-17.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/current/release-9-5-12.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/current/release-9-6-8.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/current/release-10-3.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL version 9.3.22 / 9.4.17 / 9.5.12 /
9.6.8 / 10.3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1058");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

#  9.3.22 / 9.4.17 / 9.5.12 / 9.6.8 / 10.3
constraints = [
  { "min_version" : "9.3", "fixed_version" : "9.3.22" },
  { "min_version" : "9.4", "fixed_version" : "9.4.17" },
  { "min_version" : "9.5", "fixed_version" : "9.5.12" },
  { "min_version" : "9.6", "fixed_version" : "9.6.8" },
  { "min_version" : "10.0", "fixed_version" : "10.3" }
];

vcf::postgresql::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
