#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(83818);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/04");

  script_cve_id("CVE-2015-3165", "CVE-2015-3166", "CVE-2015-3167");
  script_bugtraq_id(74787, 74789, 74790);

  script_name(english:"PostgreSQL 9.0 < 9.0.20 / 9.1 < 9.1.16 / 9.2 < 9.2.11 / 9.3 < 9.3.7 / 9.4 < 9.4.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 9.0.x prior
to 9.0.20, 9.1.x prior to 9.1.16, 9.2.x prior to 9.2.11, 9.3.x prior
to 9.3.7, or 9.4.x prior to 9.4.2. It is, therefore, affected by
multiple vulnerabilities :

  - A double free memory error exists after authentication
    timeout, which a remote attacker can utilize to cause
    the program to crash. (CVE-2015-3165)

  - A flaw exists in the printf() functions due to a failure
    to check for errors. A remote attacker can use this to
    gain access to sensitive information. (CVE-2015-3166)

  - pgcrypto has multiple error messages for decryption
    with an incorrect key. A remote attacker can use this
    to recover keys from other systems. (CVE-2015-3167)");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/about/news/1587/");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/9.0/release-9-0-20.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/9.1/release-9-1-16.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/9.2/release-9-2-11.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.3/static/release-9-3-7.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/9.4/release-9-4-2.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL 9.0.20 / 9.1.16 / 9.2.11 / 9.3.7 / 9.4.2 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3166");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("postgresql_version.nbin");
  script_require_ports("Services/postgresql", 5432);

  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"postgresql", default:5432, exit_on_fail:TRUE);

version = get_kb_item_or_exit('database/'+port+'/postgresql/version');
source = get_kb_item_or_exit('database/'+port+'/postgresql/source');
database = get_kb_item('database/'+port+'/postgresql/database_name');

get_backport_banner(banner:source);
if (backported && report_paranoia < 2) audit(AUDIT_BACKPORT_SERVICE, port, 'PostgreSQL server');

ver = split(version, sep:'.');
for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] == 9 && ver[1] == 0 && ver[2] < 20) ||
  (ver[0] == 9 && ver[1] == 1 && ver[2] < 16) ||
  (ver[0] == 9 && ver[1] == 2 && ver[2] < 11) ||
  (ver[0] == 9 && ver[1] == 3 && ver[2] < 7) ||
  (ver[0] == 9 && ver[1] == 4 && ver[2] < 2)
)
{
  if (report_verbosity > 0)
  {
    report = '';
    if(database)
      report += '\n  Database name     : ' + database ;
    report +=
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 9.0.20 / 9.1.16 / 9.2.11 / 9.3.7 / 9.4.2\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'PostgreSQL', port, version);
