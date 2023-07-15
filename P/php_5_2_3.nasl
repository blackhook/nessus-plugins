#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25368);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2007-1887",
    "CVE-2007-1900",
    "CVE-2007-2756",
    "CVE-2007-2872",
    "CVE-2007-3007"
  );
  script_bugtraq_id(
    23235,
    23359,
    24089,
    24259,
    24261
  );

  script_name(english:"PHP < 5.2.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple flaws.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP installed on the remote
host is older than 5.2.3. It is, therefore, affected by multiple
vulnerabilities:

  - A buffer overflow in the sqlite_decode_function() in
    the bundled sqlite library could allow context-dependent
    attackers to execute arbitrary code. (CVE-2007-1887)

  - A CRLF injection vulnerability in the
    FILTER_VALIDATE_EMAIL filter could allow an attacker to
    inject arbitrary email headers via a special email
    address. This only affects Mandriva Linux 2007.1.
    (CVE-2007-1900)

  - An infinite-loop flaw was discovered in the PHP gd
    extension. A script that could be forced to process PNG
    images from an untrusted source could allow a remote
    attacker to cause a denial of service. (CVE-2007-2756)

  - An integer overflow flaw was found in the
    chunk_split() function that ould possibly execute
    arbitrary code as the apache user if a remote attacker
    was able to pass arbitrary data to the third argument of
    chunk_split() (CVE-2007-2872).

  - An open_basedir and safe_mode restriction bypass which 
    could allow context-dependent attackers to determine the
    existence of arbitrary files. (CVE-2007-3007)");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_2_3.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-1887");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

if (version =~ "^5\.[01]\." ||
    version =~ "^5\.2\.[0-2]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.2.3\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
