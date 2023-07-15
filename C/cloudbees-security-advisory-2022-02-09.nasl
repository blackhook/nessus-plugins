#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158672);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-43859", "CVE-2022-0538");

  script_name(english:"Jenkins Enterprise and Operations Center 2.277.x < 2.277.43.0.6 / 2.303.x < 2.303.30.0.5 / 2.319.3.3 Multiple DoS (CloudBees Security Advisory 2022-02-09)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple DoS vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.277.x prior to
2.277.43.0.6, 2.303.x prior to 2.303.30.0.5, or 2.x prior to 2.319.3.3. It is, therefore, affected by multiple
vulnerabilities:

  - XStream is an open source java library to serialize objects to XML and back again. Versions prior to
    1.4.19 may allow a remote attacker to allocate 100% CPU time on the target system depending on CPU type or
    parallel execution of such a payload resulting in a denial of service only by manipulating the processed
    input stream. XStream 1.4.19 monitors and accumulates the time it takes to add elements to collections and
    throws an exception if a set threshold is exceeded. Users are advised to upgrade as soon as possible.
    Users unable to upgrade may set the NO_REFERENCE mode to prevent recursion. See GHSA-rmr5-cpv2-vgjf for
    further details on a workaround if an upgrade is not possible. (CVE-2021-43859)

  - Jenkins 2.333 and earlier, LTS 2.319.2 and earlier defines custom XStream converters that have not been
    updated to apply the protections for the vulnerability CVE-2021-43859 and allow unconstrained resource usage. (CVE-2022-0538)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.cloudbees.com/security-advisories/cloudbees-security-advisory-2022-02-09
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6b52fea");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.277.43.0.6, 2.303.30.0.5, 2.319.3.3, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0538");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Jenkins');

var constraints = [
  { 'min_version' : '2.277',  'fixed_version' : '2.277.43.0.6', 'edition' : make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2.303',  'fixed_version' : '2.303.30.0.5', 'edition' : make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2',      'fixed_version' : '2.319.3.3',    'edition' : make_list('Enterprise', 'Operations Center'), 'rolling_train' : TRUE },
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
