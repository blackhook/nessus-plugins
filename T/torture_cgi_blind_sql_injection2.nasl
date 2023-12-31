#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43160);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"CGI Generic SQL Injection (blind, time based)");

  script_set_attribute(attribute:"synopsis", value:
"A CGI application hosted on the remote web server is potentially
prone to SQL injection attack.");
  script_set_attribute(attribute:"description", value:
"By sending specially crafted parameters to one or more CGI scripts
hosted on the remote web server, Nessus was able to get a slower
response, which suggests that it may have been able to modify the
behavior of the application and directly access the underlying
database. 

An attacker may be able to exploit this issue to bypass
authentication, read confidential data, modify the remote database, or
even take control of the remote operating system. 

Note that this script is experimental and may be prone to false
positives.");
  script_set_attribute(attribute:"see_also", value:"http://www.securiteam.com/securityreviews/5DP0N1P76E.html");
  # https://web.archive.org/web/20101230192555/http://www.securitydocs.com/library/2651
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed792cf5");
  script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/w/page/13246963/SQL%20Injection");
  script_set_attribute(attribute:"solution", value:
"Modify the affected CGI scripts so that they properly escape
arguments.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 77, 89, 713, 722, 727, 751, 801, 810, 928, 929);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl", "torture_cgi_load_estimation1.nasl", "mssqlserver_detect.nasl", "postgresql_detect.nasl", "mysql_version.nasl");
  script_require_keys("Settings/enable_web_app_tests");
  script_require_ports("Services/www", 80);
  script_timeout(43200);

  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi.inc");
include("url_func.inc");


##############

t0 = get_read_timeout();
port = torture_cgi_init(vul:'ST');

#### Identify the SQL backend, if possible ####

nDB = 0;
if (! thorough_tests)
{
  db = extract_sql_backend_from_kb(port: port, count_only: 1);
  db_keys = keys(db);
  if (isnull(db_keys)) nDB = 0; else nDB = max_index(db_keys); 

  l = get_kb_list("MSSQL/*/Version");
  if ( !isnull(l) && max_index(l) > 0 ) db["MS SQL Server"] ++;
  l = get_kb_list("Services/postgresql");
  if (! isnull(l) && max_index(l) > 0) db["PostgreSQL"] ++;
  l = get_kb_list("Services/mysql");
  if (! isnull(l) && max_index(l) > 0) db["MySQL"] ++;;
  # DB2 is not necessary now
}

##### Choose poisons ####

# "DeLaY" will be replaced by the correct value. Mind the case!
# White spaces will be replace by %20 by my_encode(). Other special characters
# do not need to be encoded.
i = 0;
# MySQL 5
if (nDB == 0 || db["MySQL"] > 0) {
debug_print(level:2, 'Trying MySQL attacks on port ', port, '\n');
poison[i++] = "' AND SLEEP(DeLaY)='";
poison[i++] = " AND SLEEP(DeLaY)=0";
poison[i++] = ' AND 0 IN (SELECT SLEEP(DeLaY)) -- ';
poison[i++] = "' AND 0 IN (SELECT SLEEP(DeLaY)) -- ";
}
# MS SQL
if (nDB == 0 || db["MS SQL Server"] > 0) {
debug_print(level:2, 'Trying MS SQL attacks on port ', port, '\n');
poison[i++] = "';WAITFOR DELAY '00:00:DeLaY';--";
poison[i++] = "');WAITFOR DELAY '00:00:DeLaY';--";
poison[i++] = "'));WAITFOR DELAY '00:00:DeLaY';--";
poison[i++] = ";WAITFOR DELAY '00:00:DeLaY';--";
poison[i++] = ");WAITFOR DELAY '00:00:DeLaY';--";
poison[i++] = "));WAITFOR DELAY '00:00:DeLaY';--";
}
# PostgreSQL 8.2 (pg_sleep does not exist in 8.0)
if (nDB == 0 || db["PostgreSQL"] > 0) {
debug_print("Trying PostgreSQL attacks on port ", port);
poison[i++] = "';SELECT pg_sleep(DeLaY);--";
poison[i++] = "');SELECT pg_sleep(DeLaY);--";
poison[i++] = "'));SELECT pg_sleep(DeLaY);--";
poison[i++] = ";SELECT pg_sleep(DeLaY);--";
poison[i++] = ");SELECT pg_sleep(DeLaY);--";
poison[i++] = "));SELECT pg_sleep(DeLaY);--";
}
# Handling Oracle is too complex.
# No recipe for DB2 yet.
if (i == 0) exit(0, "No web poison was selected on port "+port+".");

################

torture_cgi_delay(port: port, vul: "ST");
