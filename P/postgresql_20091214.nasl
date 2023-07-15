#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63348);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/04");

  script_cve_id("CVE-2009-4034", "CVE-2009-4136");
  script_bugtraq_id(37333, 37334);

  script_name(english:"PostgreSQL 7.4 < 7.4.27 / 8.0 < 8.0.23 / 8.1 < 8.1.19 / 8.2 < 8.2.15 / 8.3 < 8.3.9 / 8.4 < 8.4.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 7.4 prior to
7.4.27, 8.0 prior to 8.0.23, 8.1 prior to 8.1.19, 8.2 prior to 8.2.15,
8.3 prior to 8.3.9 or 8.4 prior to 8.4.2.  As such, it is potentially
affected by multiple vulnerabilities :

  - NULL bytes in SSL Certificates can be used to falsify 
    client or server authentication. (CVE-2009-4034)

  - Privilege escalation is possible via changing session
    state in an index function. (CVE-2009-4136)");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/about/news/1170/");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/7.4/release-7-4-27.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/8.0/release-8-0-23.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/8.1/release-8-1-19.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/8.2/release-8-2-15.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/8.3/release-8-3-9.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/8.4/release-8-4-2.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL 7.4.27 / 8.0.23 / 8.1.19 / 8.2.15 / 8.3.9 / 8.4.2
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  (ver[0] == 7 && ver[1] == 4 && ver[2] < 27) ||
  (ver[0] == 8 && ver[1] == 0 && ver[2] < 23) ||
  (ver[0] == 8 && ver[1] == 1 && ver[2] < 19) ||
  (ver[0] == 8 && ver[1] == 2 && ver[2] < 15) ||
  (ver[0] == 8 && ver[1] == 3 && ver[2] < 9) ||
  (ver[0] == 8 && ver[1] == 4 && ver[2] < 2) 
)
{
  if (report_verbosity > 0)
  {
    report = '';
    if(database)
      report += '\n  Database name     : ' + database;
    report +=
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.4.27 / 8.0.23 / 8.1.19 / 8.2.15 / 8.3.9 / 8.4.2\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'PostgreSQL', port, version);
