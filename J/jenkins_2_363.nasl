#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164898);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/09");

  script_cve_id("CVE-2022-2048");

  script_name(english:"Jenkins LTS < 2.361.1 / Jenkins weekly < 2.363");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its its self-reported version number, the version of Jenkins running on the remote web server is Jenkins
LTS prior to 2.361.1 or Jenkins weekly prior to 2.363. It is, therefore, affected by a vulnerability:

  - In Eclipse Jetty HTTP/2 server implementation, when encountering an invalid HTTP/2 request, the error
    handling has a bug that can wind up not properly cleaning up the active connections and associated
    resources. This can lead to a Denial of Service scenario where there are no enough resources left to
    process good requests. (CVE-2022-2048)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2022-09-09");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins weekly to version 2.363 or later, or Jenkins LTS to version 2.361.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2048");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
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

var constraints = [
  { 'max_version' : '2.362', 'fixed_version' : '2.363', 'edition' : 'Open Source' },
  { 'max_version' : '2.346.3', 'fixed_version' : '2.361.1', 'edition' : 'Open Source LTS' }
];

var app_info = vcf::combined_get_app_info(app:'Jenkins');

vcf::jenkins::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
