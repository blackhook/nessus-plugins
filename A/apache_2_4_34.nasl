#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111788);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-1333", "CVE-2018-8011");
  script_xref(name:"IAVA", value:"2021-A-0259-S");

  script_name(english:"Apache 2.4.x < 2.4.34 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache running on the remote
host is 2.4.x prior to 2.4.34. It is, therefore, affected by the
following vulnerabilities:

  - By specially crafting HTTP/2 requests, workers would be
    allocated 60 seconds longer than necessary, leading to
    worker exhaustion and a denial of service. (CVE-2018-1333)

  - By specially crafting HTTP requests, the mod_md challenge
    handler would dereference a NULL pointer and cause the
    child process to segfault. This could be used to DoS the
    server. (CVE-2018-8011)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.4.34");
  script_set_attribute(attribute:"see_also", value:"https://httpd.apache.org/security/vulnerabilities_24.html#2.4.34");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.34 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1333");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:httpd");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { "min_version" : "2.4", "fixed_version" : "2.4.34" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
