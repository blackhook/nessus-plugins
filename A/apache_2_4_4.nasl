#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64893);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2012-3499", "CVE-2012-4558");
  script_bugtraq_id(58165);

  script_name(english:"Apache 2.4.x < 2.4.4 Multiple XSS Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by multiple cross-site scripting
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 2.4.x running on the
remote host is prior to 2.4.4. It is, therefore, affected by the
following cross-site scripting vulnerabilities :

  - Errors exist related to the modules mod_info,
    mod_status, mod_imagemap, mod_ldap, and mod_proxy_ftp
    and unescaped hostnames and URIs that could allow cross-
    site scripting attacks. (CVE-2012-3499)

  - An error exists related to the mod_proxy_balancer
    module's manager interface that could allow cross-site
    scripting attacks. (CVE-2012-4558)

Note that Nessus did not actually test for these issues, but instead
has relied on the version in the server's banner.");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.4.4");
  script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/security/vulnerabilities_24.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.4 or later. Alternatively, ensure that
the affected modules are not in use.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4558");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2022 Tenable Network Security, Inc.");

  script_dependencies("apache_http_version.nasl", "apache_http_server_nix_installed.nbin", "apache_httpd_win_installed.nbin");
  script_require_keys("installed_sw/Apache");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');


app_info = vcf::apache_http_server::combined_get_app_info(app:'Apache');

constraints = [
  { 'min_version' : '2.3.0', 'fixed_version' : '2.4.4' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
