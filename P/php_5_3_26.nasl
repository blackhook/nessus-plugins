#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66842);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-2110", "CVE-2013-4635");
  script_bugtraq_id(60411, 60731);

  script_name(english:"PHP 5.3.x < 5.3.26 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is potentially
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP 5.3.x installed on the
remote host is prior to 5.3.26.  It is, therefore, potentially affected
by the following vulnerabilities:

  - An error exists in the function 'php_quot_print_encode'
    in the file 'ext/standard/quot_print.c' that could allow
    a heap-based buffer overflow when attempting to parse
    certain strings (Bug #64879)

  - An integer overflow error exists related to the value
    of 'JEWISH_SDN_MAX' in the file 'ext/calendar/jewish.c'
    that could allow denial of service attacks. (Bug #64895)

Note that this plugin does not attempt to exploit these
vulnerabilities, but instead relies only on PHP's self-reported
version number.");
  # https://github.com/php/php-src/commit/93e0d78ec655f59ebfa82b2c6f8486c43651c1d0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60cbc5f0");
  # http://git.php.net/?p=php-src.git;a=blobdiff;f=ext/calendar/jewish.c;h=fcc0e5c0b878ebdd41dfeaecf148b755cd5e6f2d;hp=1e7a06c8a6dd0d6bf3b24f912a7fd40b53cbef69;hb=c50cef1dc54ffd1d0fb71d1afb8b2c3cb3c5b6ef;hpb=d4ad8898247da4eca2221e564eb8c025bc783a0b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8456482e");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.3.26");
  script_set_attribute(attribute:"solution", value:
"Apply the vendor patch or upgrade to PHP version 5.3.26 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4635");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2022 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
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

# Check that it is the correct version of PHP
if (version =~ "^5(\.3)?$") exit(1, "The banner from the PHP install associated with port "+port+" - "+version+" - is not granular enough to make a determination.");
if (version !~ "^5\.3\.") audit(AUDIT_NOT_DETECT, "PHP version 5.3.x", port);

if (version =~ "^5\.3\.([0-9]|1[0-9]|2[0-5])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : '+source +
      '\n  Installed version : '+version+
      '\n  Fixed version     : 5.3.26\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
