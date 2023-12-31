#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(89682);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Drupal 6.x < 6.38 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Drupal running on the remote web server is 6.x prior to
6.38. It is, therefore, affected by the following vulnerabilities :

  - A flaw exists in the deserialization of user-supplied
    session data. An authenticated, remote attacker can
    exploit this, via truncated session data, to execute
    arbitrary code.

  - A flaw exists in the XML-RPC system due to a failure to
    limit the number of simultaneous calls being made to the
    same method. A remote attacker can exploit this to
    facilitate brute-force attacks.

  - A cross-site redirection vulnerability exists due to
    improper validation of unspecified input before
    returning it to the user, which can allow the current
    path to be filled-in with an external URL. A remote
    attacker can exploit this, via a crafted link, to
    redirect a user to a malicious web page of the
    attacker's choosing that targets weaknesses in the
    client-side software or is used for phishing attacks.

  - A flaw exists that allows input, such as JavaScript, to
    be submitted for form buttons even if '#access' is set
    to FALSE in the server-side form definition. An
    authenticated, remote attacker can exploit this to
    bypass access restrictions.

  - A flaw exists in the drupal_set_header() function due to
    improper sanitization of user-supplied input passed as
    the header value. A remote attacker can exploit this,
    via crafted content containing line breaks, to set
    arbitrary headers.

  - A flaw exists in the drupal_goto() function due to a
    failure to properly validate the content of the
    $_REQUEST['destination'] value before returning it
    to the user. A remote attacker can exploit this, via a
    crafted link, to redirect a user to a malicious web
    page of the attacker's choosing that targets weaknesses
    in the client-side software or is used for phishing
    attacks.

  - An unspecified reflected file download flaw exists that
    allows an attacker to trick a user into downloading and
    running a file with arbitrary JSON-encoded content.

  - A flaw exists, related to how the user_save() API is
    utilized, due to assigning improper roles when saving
    user accounts. An authenticated, remote attacker can
    exploit this, via crafted data added to a form or array,
    to gain elevated privileges.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-CORE-2016-001");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/drupal-6.38-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 6.38 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Drupal";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
url = build_url(qs:dir, port:port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version == "6") audit(AUDIT_VER_NOT_GRANULAR, app, port, version);
if (version !~ "^6\.") audit(AUDIT_WEB_APP_NOT_INST, app + " 6.x", port);

if (version =~ "^6\.([0-9]|[1-2][0-9]|3[0-7])($|[^0-9])")
  security_report_v4(
    port:port,
    severity:SECURITY_HOLE,
    extra:
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.38' +
      '\n'
  );
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
