#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155631);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/07");

  script_cve_id(
    "CVE-2021-21685",
    "CVE-2021-21686",
    "CVE-2021-21687",
    "CVE-2021-21688",
    "CVE-2021-21689",
    "CVE-2021-21690",
    "CVE-2021-21691",
    "CVE-2021-21692",
    "CVE-2021-21693",
    "CVE-2021-21694",
    "CVE-2021-21695",
    "CVE-2021-21696",
    "CVE-2021-21697",
    "CVE-2021-21698"
  );

  script_name(english:"Jenkins Enterprise and Operations Center < 2.277.43.0.2 / 2.303.3.3 Multiple Vulnerabilities (CloudBees Security Advisory 2021-11-04)");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins Enterprise or Jenkins Operations Center running on the remote web server is 2.277.x prior to
2.277.43.0.2, or 2.x prior to 2.303.3.3. It is, therefore, affected by multiple vulnerabilities, including the
following:

  - Agent processes are able to completely bypass file path filtering by wrapping the file operation in an
    agent file path in Jenkins 2.318 and earlier, LTS 2.303.2 and earlier. (CVE-2021-21690)

  - Creating symbolic links is possible without the 'symlink' agent-to-controller access control permission in
    Jenkins 2.318 and earlier, LTS 2.303.2 and earlier. (CVE-2021-21691)

  - FilePath#renameTo and FilePath#moveAllChildrenTo in Jenkins 2.318 and earlier, LTS 2.303.2 and earlier
    only check 'read' agent-to-controller access permission on the source path, instead of 'delete'.
    (CVE-2021-21692)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cloudbees.com/cloudbees-security-advisory-2021-11-04");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins Enterprise or Jenkins Operations Center to version 2.277.43.0.2, 2.303.3.3, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21696");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Jenkins');

var constraints = [
  { 'min_version' : '2.277',  'fixed_version' : '2.277.43.0.2', 'edition' : make_list('Enterprise', 'Operations Center') },
  { 'min_version' : '2',      'fixed_version' : '2.303.3.3',    'edition' : make_list('Enterprise', 'Operations Center'), 'rolling_train' : TRUE },
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
