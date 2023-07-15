#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122060);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2017-15710",
    "CVE-2017-15715",
    "CVE-2018-1283",
    "CVE-2018-1301",
    "CVE-2018-1302",
    "CVE-2018-1303",
    "CVE-2018-1312"
  );
  script_bugtraq_id(
    103512,
    103515,
    103524,
    103525,
    103528,
    104584,
    106158
  );

  script_name(english:"Apache 2.4.x < 2.4.33 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache running on the remote
host is 2.4.x prior to 2.4.33. It is, therefore, affected by 
multiple vulnerabilities:

  - An out of bounds write vulnerability exists in mod_authnz_ldap
    with AuthLDAPCharsetConfig enabled. An unauthenticated, remote 
    attacker can exploit this, via the Accept-Language header value, 
    to cause the application to stop responding. (CVE-2017-15710)
 
  - An arbitrary file upload vulnerability exists in the FilesMatch
    component where a malicious filename can be crafted to match the
    expression check for a newline character. An unauthenticated, 
    remote attacker can exploit this, via newline character, to 
    upload arbitrary files on the remote host subject to the 
    privileges of the user. (CVE-2017-15715)

  - A session management vulnerability exists in the 
    mod_session component due to SessionEnv being enabled and 
    forwarding it's session data to the CGI Application. An 
    unauthenticated, remote attacker can exploit this, via 
    tampering the HTTP_SESSION and using a session header, to 
    influence content. (CVE-2018-1283)

  - An out of bounds access vulnerability exists when the size limit
    is reached. An unauthenticated, remote attacker can exploit this,
    to cause the Apache HTTP Server to crash. (CVE-2018-1301)

  - A write after free vulnerability exists in HTTP/2 stream due to 
    a NULL pointer being written to an area of freed memory. An 
    unauthenticated, remote attacker can exploit this to execute 
    arbitrary code. (CVE-2018-1302)
  
  - An out of bounds read vulnerability exists in mod_cache_socache.
    An unauthenticated, remote attacker can exploit this, via a 
    specially crafted HTTP request header to cause the application 
    to stop responding. (CVE-2018-1303)

  - A weak digest vulnerability exists in the HTTP digest 
    authentication challenge.  An unauthenticated, remote attacker 
    can exploit this in a cluster of servers configured to use a 
    common digest authentication, to replay HTTP requests across 
    servers without being detected. (CVE-2018-1312)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.4.33");
  script_set_attribute(attribute:"see_also", value:"https://httpd.apache.org/security/vulnerabilities_24.html#2.4.33");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.33 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1312");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:httpd");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl", "apache_http_server_nix_installed.nbin", "apache_httpd_win_installed.nbin");
  script_require_keys("installed_sw/Apache");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');


app_info = vcf::apache_http_server::combined_get_app_info(app:'Apache');

constraints = [
  { "min_version" : "2.4.0", "fixed_version" : "2.4.33" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
