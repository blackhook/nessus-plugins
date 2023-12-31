#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68996);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2012-4733",
    "CVE-2013-3368",
    "CVE-2013-3369",
    "CVE-2013-3370",
    "CVE-2013-3371",
    "CVE-2013-3372",
    "CVE-2013-3373",
    "CVE-2013-3374",
    "CVE-2013-5587"
  );
  script_bugtraq_id(
    60083,
    60091,
    60093,
    60094,
    60095,
    60096,
    60105,
    60106,
    62014
  );

  script_name(english:"Request Tracker 3.8.x < 3.8.17 / 4.x < 4.0.13 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a Perl application that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Best Practical
Solutions Request Tracker (RT) running on the remote web server is
version 3.8.x prior to 3.8.17 or version 4.x prior to 4.0.13. It is,
therefore, potentially affected by the following vulnerabilities :

  - A flaw exists that allows a remote, authenticated
    attacker with 'ModifyTicket' privileges to gain access
    to 'DeleteTicket' privileges, allowing tickets to be
    deleted without proper authorization. (CVE-2012-4733)

  - A flaw exists where the 'rt' command-line tool uses
    predictable temporary files. This allows a local
    attacker, using a symlink, to overwrite arbitrary
    files. (CVE-2013-3368)

  - A flaw exists that allows a remote, authenticated
    attacker who has permissions to view the administration
    pages to call arbitrary Mason components without the
    control of arguments (CVE-2013-3369)

  - A flaw exists where the application does not restrict
    direct requests to private callback components.
    (CVE-2013-3370)

  - A cross-site scripting vulnerability exists related to
    attachment file names that allows a remote attacker to
    inject arbitrary script or HTML. (CVE-2013-3371)

  - An unspecified flaw exists that allows a remote attacker
    to inject multiple Content-Disposition HTTP headers and
    possibly conduct cross-site scripting attacks.
    (CVE-2013-3372)

  - A flaw exists in the email templates that allows a
    remote attacker to inject MIME headers in email
    generated by the application. (CVE-2013-3373)

  - An information disclosure vulnerability exists due to
    the re-use of the Apache::Session::File session store.
    (CVE-2013-3374)

  - A flaw exists due to improper validation of URLs in
    tickets when the 'MakeClicky' component is enabled,
    which allows cross-site scripting attacks. Note this
    flaw only affects the RT 4.x branch. (CVE-2013-5587)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://lists.bestpractical.com/pipermail/rt-announce/2013-May/000227.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c8a91ea");
  # http://lists.bestpractical.com/pipermail/rt-announce/2013-May/000226.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e79fb8ab");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2013/May/123");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Request Tracker 3.8.17 / 4.0.13 or later, or apply the
patch listed in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bestpractical:rt");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2022 Tenable Network Security, Inc.");

  script_dependencies("rt_detect.nasl");
  script_require_keys("installed_sw/RT", "Settings/ParanoidReport");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "RT";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

path = install['path'];
install_url = build_url(port:port, qs:path + "/");
version = install['version'];

# Versions 3.8.0 < 3.8.17 are affected.
# Versions 4.0.0 < 4.0.13 are affected.
if (
  version =~ "^3\.8\.([0-9]|1[0-6])($|[^0-9])" ||
  version =~ "^4\.0\.([0-9]|1[0-2])($|[^0-9])"
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.8.17 / 4.0.13\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
