#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100995);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2017-3167",
    "CVE-2017-3169",
    "CVE-2017-7659",
    "CVE-2017-7668",
    "CVE-2017-7679"
  );
  script_bugtraq_id(
    99132,
    99134,
    99135,
    99137,
    99170
  );

  script_name(english:"Apache 2.2.x < 2.2.33-dev / 2.4.x < 2.4.26 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache running on the remote
host is 2.2.x prior to 2.2.33-dev or 2.4.x prior to 2.4.26. It is,
therefore, affected by the following vulnerabilities :

  - An authentication bypass vulnerability exists due to
    third-party modules using the ap_get_basic_auth_pw()
    function outside of the authentication phase. An
    unauthenticated, remote attacker can exploit this to
    bypass authentication requirements. (CVE-2017-3167)

  - A NULL pointer dereference flaw exists due to
    third-party module calls to the mod_ssl
    ap_hook_process_connection() function during an HTTP
    request to an HTTPS port. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (CVE-2017-3169)

  - A NULL pointer dereference flaw exists in mod_http2 that
    is triggered when handling a specially crafted HTTP/2
    request. An unauthenticated, remote attacker can exploit
    this to cause a denial of service condition. Note that
    this vulnerability does not affect 2.2.x.
    (CVE-2017-7659)

  - An out-of-bounds read error exists in the
    ap_find_token() function due to improper handling of
    header sequences. An unauthenticated, remote attacker
    can exploit this, via a specially crafted header
    sequence, to cause a denial of service condition.
    (CVE-2017-7668)

  - An out-of-bounds read error exists in mod_mime due to
    improper handling of Content-Type response headers. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted Content-Type response header, to cause
    a denial of service condition or the disclosure of
    sensitive information. (CVE-2017-7679)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.2.32");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.4.26");
  script_set_attribute(attribute:"see_also", value:"https://httpd.apache.org/security/vulnerabilities_22.html");
  script_set_attribute(attribute:"see_also", value:"https://httpd.apache.org/security/vulnerabilities_24.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.2.33-dev / 2.4.26 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7679");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl", "apache_http_server_nix_installed.nbin", "apache_httpd_win_installed.nbin");
  script_require_keys("installed_sw/Apache");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');


app_info = vcf::apache_http_server::combined_get_app_info(app:'Apache');

constraints = [
  { "min_version" : "2.2", "fixed_version" : "2.2.33" },
  { "min_version" : "2.4", "fixed_version" : "2.4.26" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
