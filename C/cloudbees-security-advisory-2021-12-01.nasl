#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158092);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-35517", "CVE-2021-37714");

  script_name(english:"Jenkins Enterprise and Operations Center < 2.277.43.0.3 / 2.319.1.5 Multiple Vulnerabilities (CloudBees Security Advisory 2021-12-01)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.277.x prior to
2.277.43.0.3, or 2.x prior to 2.319.1.5. It is, therefore, affected by a multiple vulnerabilities, including the
following:

  - When reading a specially crafted TAR archive, Compress can be made to allocate large amounts of memory
    that finally leads to an out of memory error even for very small inputs. This could be used to mount a
    denial of service attack against services that use Compress' tar package. (CVE-2021-35517)

  - jsoup is a Java library for working with HTML. Those using jsoup versions prior to 1.14.2 to parse
    untrusted HTML or XML may be vulnerable to DOS attacks. If the parser is run on user supplied input, an
    attacker may supply content that causes the parser to get stuck (loop indefinitely until cancelled), to
    complete more slowly than usual, or to throw an unexpected exception. This effect may support a denial of
    service attack. The issue is patched in version 1.14.2. There are a few available workarounds. Users may
    rate limit input parsing, limit the size of inputs based on system resources, and/or implement thread
    watchdogs to cap and timeout parse runtimes. (CVE-2021-37714)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.cloudbees.com/security-advisories/cloudbees-security-advisory-2021-12-01
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ada20860");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.277.43.0.3, 2.319.1.5, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37714");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/16");

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
  { 'min_version' : '2.277',  'fixed_version' : '2.277.43.0.3', 'edition' : make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2',      'fixed_version' : '2.319.1.5',    'edition' : make_list('Enterprise', 'Operations Center'), 'rolling_train' : TRUE },
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
