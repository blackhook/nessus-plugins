# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106232);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/22");

  script_name(english:"Apache ServerTokens Information Disclosure");
  script_summary(english:"Checks if the Apache ServerTokens setting.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server discloses information via HTTP headers.");
  script_set_attribute(attribute:"description", value:
"The HTTP headers sent by the remote web server disclose information
that can aid an attacker, such as the server version, operating system,
and module versions.");
  script_set_attribute(attribute:"solution", value:
"Change the Apache ServerTokens configuration value to 'Prod'");
  script_set_attribute(attribute:"see_also",value:"https://www.owasp.org/index.php/SCG_WS_Apache");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score from an in depth analysis done by Tenable");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Apache", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_install_count(app_name:"Apache", exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:"Apache", port:port, exit_if_unknown_ver:TRUE);

source = get_kb_item_or_exit('www/apache/'+port+'/source');

report = '';
if (!empty_or_null(install["modules"]) || !empty_or_null(install["os"]) ||
    !empty_or_null(install["version"]))
{
  report = '\nThe Apache server listening on port ' + port + ' contains\n' +
           'sensitive information in the HTTP Server field.\n' +
           '\n' +
           source +
           '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);
}

# this should be unreachable
audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, install["version"]);

