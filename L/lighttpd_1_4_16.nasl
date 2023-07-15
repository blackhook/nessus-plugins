#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106623);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id(
    "CVE-2007-3946",
    "CVE-2007-3947",
    "CVE-2007-3948",
    "CVE-2007-3949",
    "CVE-2007-3950"
  );
  script_bugtraq_id(24967);

  script_name(english:"lighttpd < 1.4.16 Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of lighttpd running on the remote
host is prior to 1.4.16. It is, therefore, affected by multiple
vulnerabilities :

  - mod_auth allows remote attackers to cause a denial of service
    via unspecified vectors involving (1) a memory leak, (2) use
    of md5-sess without a cnonce, (3) base64 encoded strings, and
    (4) trailing whitespace in the Auth-Digest header.
    (CVE-2007-3946)

  - The server allows remote attackers to cause a denial of
    service by sending an HTTP request with duplicate headers.
    (CVE-2007-3947)

  - The server might accept more connections than the configured
    maximum, which allows remote attackers to cause a denial of
    service via a large number of connection attempts.
    (CVE-2007-3948)

  - mod_access ignores trailing / (slash) characters in the URL,
    which allows remote attackers to bypass url.access-deny settings
    (CVE-2007-3949)

  - The server, when run on 32 bit platforms, allows remote attackers
    to cause a denial of service (daemon crash) via unspecified vectors
    involving the use of incompatible format specifiers in certain
    debugging messages in the (1) mod_scgi, (2) mod_fastcgi, and
    (3) mod_webdav modules. (CVE-2007-3950)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to lighttpd version 1.4.16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lighttpd:lighttpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("lighttpd_detect.nasl");
  script_require_keys("installed_sw/lighttpd", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

appname = "lighttpd";
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80);
app_info = vcf::get_app_info(app:appname, port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [{"fixed_version":"1.4.16"}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
