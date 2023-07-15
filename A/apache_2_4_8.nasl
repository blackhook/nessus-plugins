#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73081);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-6438", "CVE-2014-0098");
  script_bugtraq_id(66303);

  script_name(english:"Apache 2.4.x < 2.4.8 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 2.4.x running on the
remote host is a version prior to 2.4.8. It is, therefore, affected by
the following vulnerabilities :

  - A flaw exists with the 'mod_dav' module that is caused
    when tracking the length of CDATA that has leading white
    space. A remote attacker with a specially crafted DAV
    WRITE request can cause the service to stop responding.
    (CVE-2013-6438)

  - A flaw exists in 'mod_log_config' module that is caused
    when logging a cookie that has an unassigned value. A
    remote attacker with a specially crafted request can
    cause the service to crash. (CVE-2014-0098)

Note that Nessus did not actually test for these issues, but instead
has relied on the version in the server's banner.");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.4.9");
  script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/security/vulnerabilities_24.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.9 or later. Alternatively, ensure that
the affected modules are not in use.

Note that the issues were addressed in 2.4.8, although that version
was not released.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0098");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/18");

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
  { 'min_version' : '2.3.0', 'fixed_version' : '2.4.8' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
