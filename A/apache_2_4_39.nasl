#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123642);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2019-0196",
    "CVE-2019-0197",
    "CVE-2019-0211",
    "CVE-2019-0215",
    "CVE-2019-0217",
    "CVE-2019-0220"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2019-0203");

  script_name(english:"Apache 2.4.x < 2.4.39 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache running on the remote
host is 2.4.x prior to 2.4.39. It is, therefore, affected by multiple
vulnerabilities:

  - A privilege escalation vulnerability exists in
    module scripts due to an ability to execute arbitrary
    code as the parent process by manipulating the
    scoreboard. (CVE-2019-0211)

  - An access control bypass vulnerability exists in 
    mod_auth_digest due to a race condition when running
    in a threaded server. An attacker with valid credentials
    could authenticate using another username. (CVE-2019-0217)

  - An access control bypass vulnerability exists in 
    mod_ssl when using per-location client certificate
    verification with TLSv1.3. (CVE-2019-0215)

In addition, Apache httpd is also affected by several additional 
vulnerabilities including a denial of service, read-after-free
and URL path normalization inconsistencies. 

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://httpd.apache.org/security/vulnerabilities_24.html#2.4.39
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a84bee48");
  # https://httpd.apache.org/security/vulnerabilities-httpd.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?586e6a34");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.39 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0211");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:httpd");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl", "apache_http_server_nix_installed.nbin", "apache_httpd_win_installed.nbin");
  script_require_keys("installed_sw/Apache");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');


app_info = vcf::apache_http_server::combined_get_app_info(app:'Apache');

constraints = [
  { 'min_version':'2.4', 'fixed_version':'2.4.39' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
