#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65055);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-0158");
  script_bugtraq_id(57171);

  script_name(english:"Jenkins < 1.498 / 1.480.2 and Jenkins Enterprise 1.447.x / 1.466.x < 1.447.6.1 / 1.466.12.1 Unspecified Master Cryptographic Key Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a job scheduling / management system that
is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a version of Jenkins or Jenkins Enterprise
that is affected by an information disclosure vulnerability that could
allow a remote attacker to gain access to master cryptographic key
information.  Attackers with this information may be able to execute
arbitrary code on the master host.");
  # https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory+2013-01-04
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f8bc6d8");
  # https://www.cloudbees.com/jenkins-security-advisory-2013-01-04
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd73e7b2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Jenkins 1.498 / 1.480.2, Jenkins Enterprise 1.447.6.1 /
1.466.12.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0158");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Jenkins');

var constraints = [
  { 'fixed_version' : '1.498',      'fixed_display' : '1.498 / 1.480.2',        'edition':'Open Source' },
  { 'fixed_version' : '1.480.2',    'fixed_display' : '1.498 / 1.480.2',        'edition':'Open Source LTS' },
  { 'fixed_version' : '1.447.6.1',  'fixed_display' : '1.447.6.1 / 1.466.12.1', 'edition':'Enterprise' },
  { 'min_version' : '1.466', 'fixed_version' : '1.466.12.1', 'fixed_display' : '1.447.6.1 / 1.466.12.1', 'edition':'Enterprise' }
];

vcf::jenkins::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
