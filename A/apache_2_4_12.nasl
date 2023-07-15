#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81126);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2013-5704",
    "CVE-2014-3581",
    "CVE-2014-3583",
    "CVE-2014-8109"
  );
  script_bugtraq_id(
    66550,
    71656,
    71657,
    73040
  );

  script_name(english:"Apache 2.4.x < 2.4.12 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 2.4.x running on the
remote host is prior to 2.4.12. It is, therefore, affected by the
following vulnerabilities :

  - A flaw exists in module mod_headers that can allow HTTP
    trailers to replace HTTP headers late during request
    processing, which a remote attacker can exploit to
    inject arbitrary headers. This can also cause some
    modules to function incorrectly or appear to function
    incorrectly. (CVE-2013-5704)

  - A NULL pointer dereference flaw exists in module
    mod_cache. A remote attacker, using an empty HTTP
    Content-Type header, can exploit this vulnerability to
    crash a caching forward proxy configuration, resulting
    in a denial of service if using a threaded MPM.
    (CVE-2014-3581)

  - A out-of-bounds memory read flaw exists in module
    mod_proxy_fcgi. An attacker, using a remote FastCGI
    server to send long response headers, can exploit this
    vulnerability to cause a denial of service by causing
    a buffer over-read. (CVE-2014-3583)

  - A flaw exists in module mod_lua when handling a
    LuaAuthzProvider used in multiple Require directives
    with different arguments. An attacker can exploit this
    vulnerability to bypass intended access restrictions.
    (CVE-2014-8109)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.4.12");
  script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/security/vulnerabilities_24.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.12 or later. Alternatively, ensure that
the affected modules are not in use.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-5704");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2022 Tenable Network Security, Inc.");

  script_dependencies("apache_http_version.nasl", "apache_http_server_nix_installed.nbin", "apache_httpd_win_installed.nbin");
  script_require_keys("installed_sw/Apache");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');


app_info = vcf::apache_http_server::combined_get_app_info(app:'Apache');

constraints = [
  { 'min_version' : '2.3.0', 'fixed_version' : '2.4.12' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
