#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11139);
  script_version("2.30");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"CGI Generic SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"A web application is potentially vulnerable to SQL injection.");
  script_set_attribute(attribute:"description", value:
"By providing specially crafted parameters to CGIs, Nessus was able to
get an error from the underlying database. This error suggests that
the CGI is affected by a SQL injection vulnerability.

An attacker may exploit this flaw to bypass authentication, read
confidential data, modify the remote database, or even take control of
the remote operating system.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/SQL_injection");
  script_set_attribute(attribute:"see_also", value:"http://www.securiteam.com/securityreviews/5DP0N1P76E.html");
  # https://web.archive.org/web/20101230192555/http://www.securitydocs.com/library/2651
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed792cf5");
  script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/w/page/13246963/SQL%20Injection");
  script_set_attribute(attribute:"see_also", value:"https://www.owasp.org/index.php/SQL_Injection");
  script_set_attribute(attribute:"solution", value:
"Modify the relevant CGIs so that they properly escape arguments.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 77, 89, 203, 209, 713, 717, 722, 727, 751, 801, 810, 928, 929, 933);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl", "torture_cgi_load_estimation1.nasl");
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

####

global_patterns = sql_error_patterns;

single_quote = raw_string(0x27);
double_quote = raw_string(0x22);

i = 0;
poison[i++] = single_quote;
poison[i++] = single_quote + "%22";
poison[i++] = "9%2c+9%2c+9";	# 2C = ,
poison[i++] = "bad_bad_value" + single_quote;
poison[i++] = "%3B";
poison[i++] = single_quote + " or 1=1-- ";
poison[i++] = " or 1=1-- ";
poison[i++] = "char(39)";
poison[i++] = "%27";
poison[i++] = "--+";
poison[i++] = "#";
poison[i++] = "/*";
poison[i++] = double_quote;
poison[i++] = "%22";
poison[i++] = "%2527";
poison[i++] = single_quote + "+convert(int,convert(varchar,0x7b5d))+" + single_quote;
poison[i++] = "convert(int,convert(varchar,0x7b5d))";
poison[i++] = single_quote + "+convert(varchar,0x7b5d)+" + single_quote;
poison[i++] = "convert(varchar,0x7b5d)";
poison[i++] = single_quote + "%2Bconvert(int,convert(varchar%2C0x7b5d))%2B" + single_quote;
poison[i++] = single_quote + "%2Bconvert(varchar%2C0x7b5d)%2B" + single_quote;
poison[i++] = "convert(int,convert(varchar%2C0x7b5d))";
poison[i++] = "convert(varchar%2C0x7b5d)";
# from torturecgis.nasl
poison[i++] = "whatever)";
# The next two patterns work if the application doubles single quotes 
# and truncate the output. 
if (experimental_scripts || thorough_tests)
{
poison[i++] = '\\';		# works on MySQL in a string
poison[i++] = "''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''";
poison[i++] = "a''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''";
# May be useful for XPath injections too
poison[i++] = single_quote + "--";
}


if (0)	# Disabled
{
poison[i++] = "&#39;+AND+&#39;a&#39;<&#39;b";	# FP w/ ColdFusion -- Cerberus DLN-90614-751
poison[i++] = single_quote + "UNION" + single_quote;
poison[i++] = single_quote + "bad_bad_value";
poison[i++] = single_quote + "+AND+" + single_quote;
poison[i++] = single_quote + "WHERE";
poison[i++] = single_quote + "AND";
poison[i++] = single_quote + " or " + single_quote + "a" + single_quote + "=" + single_quote + "a";
poison[i++] = single_quote + ") or (" + single_quote + "a" + single_quote + "=" + single_quote + "a";
poison[i++] = single_quote + "+AND+1=1)";
poison[i++] = single_quote + "+AND+1=1))";
poison[i++] = single_quote + "+AND+1=1#";
poison[i++] = single_quote + "+AND+1=1)#";
poison[i++] = single_quote + "+AND+1=1))#";
poison[i++] = "&#39;)+AND+(&#39;a&#39;<&#39;b";
poison[i++] = "&#39;)+AND+(&#39;a&#39;<&#39;b&#39;)/*";
poison[i++] = "&#39;)+AND+(&#39;a&#39;<&#39;b&#39;))/*";
poison[i++] = single_quote + "+or+1=1/*";
poison[i++] = single_quote + "+or+1=1)/*";
poison[i++] = single_quote + "+or+1=1))/*";
}

flaws_and_patterns = make_array();
for (i = 0; ! isnull(poison[i]); i ++)
 flaws_and_patterns[poison[i]] = "GL";
poison = NULL;	# Free memory

####

port = torture_cgi_init(vul: 'SI');

report = torture_cgis(port: port, vul: "SI");

if (strlen(report) > 0)
{
  security_hole(port:port, extra: report);
}

