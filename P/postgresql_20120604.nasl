#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63353);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/04");

  script_cve_id("CVE-2012-2143", "CVE-2012-2655");
  script_bugtraq_id(53729, 53812);

  script_name(english:"PostgreSQL 8.3 < 8.3.19 / 8.4 < 8.4.12 / 9.0 < 9.0.8 / 9.1 < 9.1.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 8.3.x prior
to 8.3.19, 8.4.x prior to 8.4.12, 9.0.x prior to 9.0.8, or 9.1.x prior
to 9.1.4.  As such, it is potentially affected by multiple
vulnerabilities :

  - Passwords containing the byte 0x80 passed to the crypt() 
    function in pgcrypto are incorrectly truncated if DES 
    encryption was used. (CVE-2012-2143)

  - SECURITY_DEFINER and SET attributes on procedural call 
    handlers are not ignored and can be used to crash the 
    server. (CVE-2012-2655)");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/about/news/1398/");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/8.3/release-8-3-19.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/8.4/release-8-4-12.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/9.0/release-9-0-8.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/9.1/release-9-1-4.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL 8.3.19 / 8.4.12 / 9.0.8 / 9.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-2143");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/30");
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
  (ver[0] == 8 && ver[1] == 3 && ver[2] < 19) ||
  (ver[0] == 8 && ver[1] == 4 && ver[2] < 12) ||
  (ver[0] == 9 && ver[1] == 0 && ver[2] < 8) || 
  (ver[0] == 9 && ver[1] == 1 && ver[2] < 4)
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
      '\n  Fixed version     : 8.3.19 / 8.4.12 / 9.0.8 / 9.1.4\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'PostgreSQL', port, version);
