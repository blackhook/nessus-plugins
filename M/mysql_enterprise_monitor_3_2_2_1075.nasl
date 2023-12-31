#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96769);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id(
    "CVE-2015-5351",
    "CVE-2015-7501",
    "CVE-2016-0635",
    "CVE-2016-0706",
    "CVE-2016-0714",
    "CVE-2016-0763"
  );
  script_bugtraq_id(
    78215,
    83324,
    83326,
    83327,
    83330,
    91869
  );
  script_xref(name:"CERT", value:"576313");

  script_name(english:"MySQL Enterprise Monitor 3.2.x < 3.2.2.1075 Multiple Vulnerabilities (January 2017 CPU)");
  script_summary(english:"Checks the version of MySQL Enterprise Monitor.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the MySQL Enterprise Monitor
application running on the remote host is 3.2.x prior to 3.2.2.1075.
It is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    bundled version of Apache Tomcat in the Manager and Host
    Manager web applications due to a flaw in the index page
    when issuing redirects in response to unauthenticated
    requests for the root directory of the application. An
    authenticated, remote attacker can exploit this to gain
    access to the XSRF token information stored in the index
    page. (CVE-2015-5351)

  - A remote code execution vulnerability exists in the 
    JMXInvokerServlet interface due to improper validation
    of Java objects before deserialization. An
    authenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2015-7501)

  - A remote code execution vulnerability exists in the
    Framework subcomponent that allows an authenticated,
    remote attacker to execute arbitrary code.
    (CVE-2016-0635)

  - An information disclosure vulnerability exists in the 
    bundled version of Apache Tomcat that allows a specially
    crafted web application to load the
    StatusManagerServlet. An authenticated, remote attacker
    can exploit this to gain unauthorized access to a list
    of all deployed applications and a list of the HTTP
    request lines for all requests currently being
    processed. (CVE-2016-0706)

  - A remote code execution vulnerability exists in the
    bundled version of Apache Tomcat due to a flaw in the
    StandardManager, PersistentManager, and cluster
    implementations that is triggered when handling
    persistent sessions. An authenticated, remote attacker
    can exploit this, via a crafted object in a session, to
    bypass the security manager and execute arbitrary code.
    (CVE-2016-0714)

  - A security bypass vulnerability exists in the bundled
    version of Apache Tomcat due to a failure to consider
    whether ResourceLinkFactory.setGlobalContext callers are
    authorized. An authenticated, remote attacker can
    exploit this, via a web application that sets a crafted
    global context, to bypass intended SecurityManager
    restrictions and read or write to arbitrary application
    data or cause a denial of service condition.
    (CVE-2016-0763)");
  # https://dev.mysql.com/doc/relnotes/mysql-monitor/3.2/en/news-3-2-2.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b87d451");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1c38e52");
  # https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c6d83db");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Enterprise Monitor version 3.2.2.1075 or later as
referenced in the January 2017 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7501");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_enterprise_monitor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_enterprise_monitor_web_detect.nasl");
  script_require_keys("installed_sw/MySQL Enterprise Monitor", "Settings/ParanoidReport");
  script_require_ports("Services/www", 18443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app  = "MySQL Enterprise Monitor";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:18443);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];
install_url = build_url(port:port, qs:"/");

fix = "3.2.2.1075";
vuln = FALSE;
if (version =~ "^3\.2($|[^0-9])" && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
  vuln = TRUE;;

if (vuln)
{
  report =
    '\n  URL               : ' + install_url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report, xsrf:TRUE);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
