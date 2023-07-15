#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76622);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2014-0117",
    "CVE-2014-0118",
    "CVE-2014-0226",
    "CVE-2014-0231",
    "CVE-2014-3523"
  );
  script_bugtraq_id(
    68678,
    68740,
    68742,
    68745,
    68747
  );
  script_xref(name:"EDB-ID", value:"34133");

  script_name(english:"Apache 2.4.x < 2.4.10 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 2.4.x running on the
remote host is prior to 2.4.10. It is, therefore, affected by the
following vulnerabilities :

  - A flaw exists in the 'mod_proxy' module that may allow
    an attacker to send a specially crafted request to a
    server configured as a reverse proxy that may cause
    the child process to crash. This could potentially
    lead to a denial of service attack. (CVE-2014-0117)

  - A flaw exists in  the 'mod_deflate' module when request
    body decompression is configured. This could allow a
    remote attacker to cause the server to consume
    significant resources. (CVE-2014-0118)

  - A flaw exists in the 'mod_status' module when a
    publicly accessible server status page is in place.
    This could allow an attacker to send a specially
    crafted request designed to cause a heap buffer
    overflow. (CVE-2014-0226)

  - A flaw exists in the 'mod_cgid' module in which CGI
    scripts that did not consume standard input may be
    manipulated in order to cause child processes to
    hang. A remote attacker may be able to abuse this
    in order to cause a denial of service.
    (CVE-2014-0231)

  - A flaw exists in WinNT MPM versions 2.4.1 to 2.4.9 when
    using the default AcceptFilter. An attacker may be able
    to specially craft requests that create a memory leak in
    the application and may eventually lead to a denial of
    service attack. (CVE-2014-3523)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.4.10");
  script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/security/vulnerabilities_24.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.10 or later. Alternatively, ensure that
the affected modules are not in use.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0226");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl", "apache_http_server_nix_installed.nbin", "apache_httpd_win_installed.nbin");
  script_require_keys("installed_sw/Apache");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');


app_info = vcf::apache_http_server::combined_get_app_info(app:'Apache');

constraints = [
  { 'min_version' : '2.3.0', 'fixed_version' : '2.4.10' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
