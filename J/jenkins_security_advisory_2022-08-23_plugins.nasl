#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164452);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/26");

  script_cve_id(
    "CVE-2021-25738",
    "CVE-2022-38663",
    "CVE-2022-38664",
    "CVE-2022-38665"
  );

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2022-08-23)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - Jenkins Git Plugin 4.11.4 and earlier does not properly mask (i.e., replace with asterisks) credentials in
    the build log provided by the Git Username and Password (`gitUsernamePassword`) credentials binding.
    (CVE-2022-38663)

  - Jenkins Job Configuration History Plugin 1165.v8cc9fd1f4597 and earlier does not escape the job name on
    the System Configuration History page, resulting in a stored cross-site scripting (XSS) vulnerability
    exploitable by attackers able to configure job names. (CVE-2022-38664)

  - Jenkins CollabNet Plugins Plugin 2.0.8 and earlier stores a RabbitMQ password unencrypted in its global
    configuration file on the Jenkins controller where it can be viewed by users with access to the Jenkins
    controller file system. (CVE-2022-38665)

  - Loading specially-crafted yaml with the Kubernetes Java Client library can lead to code execution.
    (CVE-2021-25738)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2022-08-23");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - CollabNet Plugins Plugin to version 2.0.9 or later
  - Git Plugin to version 4.11.5 or later
  - Job Configuration History Plugin to version 1166.vc9f255f45b_8a or later
  - Kubernetes Continuous Deploy Plugin: See vendor advisory

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25738");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_plugins_detect.nbin", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
include('jenkins_plugin_mappings.inc');

var constraints = [
    {'max_version' : '2.0.8', 'fixed_version' : '2.0.9', 'plugin' : jenkins_plugin_mappings['CollabNet Plugins Plugin']},
    {'max_version' : '4.11.4', 'fixed_version' : '4.11.5', 'plugin' : jenkins_plugin_mappings['Git Plugin']},
    {'max_version' : '1165', 'fixed_version' : '1166', 'fixed_display' : '1166.vc9f255f45b_8a', 'plugin' : jenkins_plugin_mappings['Job Configuration History Plugin']},
    {'max_version' : '2.3.1', 'fixed_display' : 'See vendor advisory', 'plugin' : jenkins_plugin_mappings['Kubernetes Continuous Deploy Plugin']}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
