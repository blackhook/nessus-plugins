#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109403);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-9861");
  script_bugtraq_id(103924);

  script_name(english:"CKEditor 4.5.11 < 4.9.2 Enhanced Image Plugin XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a script that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of CKEditor installed on the remote host is affected by a
cross-site scripting vulnerability.

The included 'Enhanced Image' plugin causes CKEditor to fail to 
properly sanitize user-supplied input. A remote, unauthenticated 
attacker can leverage this issue to inject arbitrary HTML and script 
code into a user's browser to be executed within the security context 
of the affected site.");
  # https://ckeditor.com/blog/CKEditor-4.9.2-with-a-security-patch-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be1255cc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version CKEditor 4.9.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-9861");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ckeditor:ckeditor");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "CKEditor";
port = get_http_port(default:80, php:TRUE);

if (thorough_tests) dirs = list_uniq(
  make_list(
    "/ckeditor",
    "/modules/ckeditor",
    "/admin/ckeditor",
    "/includes/ckeditor",
    "/lib/ckeditor",
    cgi_dirs()
  )
);
else dirs = make_list(cgi_dirs());
install_dirs = make_list();
non_vuln = make_list();

report = '';
foreach dir (dirs)
{
  # check that ckeditor.js exists
  # ~ 4.6 MiB
  res_editor = http_send_recv3(
    method      : "GET",
    port        : port,
    item        : dir + "/ckeditor.js",
    exit_on_fail: true
  );

  if ("200" >< res_editor[0]) install_dirs = make_list(install_dirs, dir);

  # check that Enhanced Image plugin is installed
  # ~ 63 KiB
  # not included in basic, standard, or full installs (the defaults)
  # can be manually selected from their web builder
  res_image2 = http_send_recv3(
    method : "GET",
    port   : port,
    item   : dir + "/plugins/image2/plugin.js"
  );

  # Check for patch
  # minimisation changes variable names to one a-z char
  if (
    "200" >< res_editor[0] &&
    "200" >< res_image2[0] &&
    "CKEDITOR.plugins.add( 'image2'," >< res_image2[2] &&
    !preg(
      string:res_editor[2],
      pattern:'var [a-z]=[a-z]&&CKEDITOR\\.tools\\.htmlEncode\\([a-z]\\)\\|\\|"\\\\x26nbsp;',
      multiline:true)
  )
  {
    report +=
      '\n' + 'Nessus was able to verify the issue by examining the ' +
      '\n' + 'output from the following requests:' +
      '\n' +
      '\n' + build_url(qs:dir + "/ckeditor.js", port:port) +
      '\n' + build_url(qs:dir + "/plugins/image2/plugin.js", port:port) +
      '\n';
    if (!thorough_tests) break;
  }
  else non_vuln = make_list(non_vuln, build_url(qs:dir, port:port));
}

if (report != '')
{
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report, xss:TRUE);
}
else if (max_index(install_dirs) == 0)
{
  audit(AUDIT_WEB_APP_NOT_INST, app, port);
}
else if (max_index(non_vuln) == 1)
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, non_vuln[0]);
}
else
{
  exit(0, "The CKEditor installs at "
      + join(non_vuln, sep:", ")
      + " are not affected.");
}
