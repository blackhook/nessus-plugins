#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154055);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2014-3577",
    "CVE-2021-21682",
    "CVE-2021-21683",
    "CVE-2021-21684"
  );
  script_xref(name:"IAVA", value:"2021-A-0460-S");

  script_name(english:"Jenkins LTS < 2.303.2 / Jenkins weekly < 2.315 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its its self-reported version number, the version of Jenkins running on the remote web server is Jenkins
LTS prior to 2.303.2 or Jenkins weekly prior to 2.315. It is, therefore, affected by multiple vulnerabilities:

  - Jenkins 2.314 and earlier, LTS 2.303.1 and earlier accepts names of jobs and other entities with a
    trailing dot character, potentially replacing the configuration and data of other entities on Windows.
    (CVE-2021-21682)

  - org.apache.http.conn.ssl.AbstractVerifier in Apache HttpComponents HttpClient before 4.3.5 and
    HttpAsyncClient before 4.0.2 does not properly verify that the server hostname matches a domain name in
    the subject's Common Name (CN) or subjectAltName field of the X.509 certificate, which allows man-in-the-
    middle attackers to spoof SSL servers via a CN= string in a field in the distinguished name (DN) of a
    certificate, as demonstrated by the foo,CN=www.apache.org string in the O field. (CVE-2014-3577)

  - The file browser in Jenkins 2.314 and earlier, LTS 2.303.1 and earlier may interpret some paths to files
    as absolute on Windows, resulting in a path traversal vulnerability allowing attackers with Overall/Read
    permission (Windows controller) or Job/Workspace permission (Windows agents) to obtain the contents of
    arbitrary files. (CVE-2021-21683)

  - Jenkins Git Plugin 4.8.2 and earlier does not escape the Git SHA-1 checksum parameters provided to commit
    notifications when displaying them in a build cause, resulting in a stored cross-site scripting (XSS)
    vulnerability. (CVE-2021-21684)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2021-10-06");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins weekly to version 2.315 or later or Jenkins LTS to version 2.303.2 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3577");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21683");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'max_version' : '2.314', 'fixed_version' : '2.315', 'edition' : 'Open Source' },
  { 'max_version' : '2.303.1', 'fixed_version' : '2.303.2', 'edition' : 'Open Source LTS' }
];

var flags = {'xss':TRUE};
vcf::jenkins::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags: flags);
