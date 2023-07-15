#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117462);
  script_version("1.2");
  script_cvs_date("Date: 2018/11/15 20:50:19");

  script_name(english:"Zinwave Series 3000 DAS Web Interface Default Credentials");
  script_summary(english:"Try logging into Zinwave Series 3000 DAS web interface using default credentials.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The administration console for the remote distributed antenna system
is protected using a known set of credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Nessus was able to log in to Zinwave Series 3000 DAS using a default
set of administrative credentials.  A remote attacker could utilize
these credentials to view and change or delete operating parameters or
switching matrix configurations or change the system configuration."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.zinwave.com/das-solutions-0");
  script_set_attribute(attribute:"solution", value:"Change passwords on any default accounts.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"default credentials");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:zinwave:3000das");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zinwave_series_3000_DAS_web_detect.nbin");
  script_exclude_keys("Settings/disable_cgi_scanning", "global_settings/supplied_logins_only");
  script_require_keys("installed_sw/Zinwave Series 3000 DAS");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("vcf.inc");
include("http.inc");

app = "Zinwave Series 3000 DAS";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443);

install = get_single_install(app_name:app, port:port);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

dir = install['path'];

install_url = build_url(port:port, qs:dir);

username = "advanced";
password = "superuser";

res = http_send_recv3(
  method:"GET",
  item:dir + '/',
  port:port,
  username:username,
  password:password,
  exit_on_fail:TRUE
);

if (res[0] !~ "^HTTP/[0-9.]+ 200" ||
    "Unauthorized" >< res[2])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app + " Web Interface", install_url);

report =
  '\n' + 'It is possible to log into the Zinwave Series 3000 DAS at the' +
  '\n' + 'following URL :' +
  '\n' +
  '\n' + install_url +
  '\n' +
  '\n' + 'with these credentials :' +
  '\n  Username : ' + username +
  '\n  Password : ' + password +
  '\n';

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
