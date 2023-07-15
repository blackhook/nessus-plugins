#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133527);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2020-2100",
    "CVE-2020-2101",
    "CVE-2020-2102",
    "CVE-2020-2103",
    "CVE-2020-2104",
    "CVE-2020-2105",
    "CVE-2020-2106"
  );

  script_name(english:"Jenkins < 2.204.2 LTS / 2.219 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins running on the remote web server is prior to
2.219 or is a version of Jenkins LTS prior to 2.204.2. It is, therefore,
affected by multiple vulnerabilities:

  - An UDP amplification reflection attack can be used in a DDoS attack
    on a Jenkins master. Within the same network, spoofed UDP packets
    could also be sent to make two Jenkins masters go into an infinite
    loop of replies to one another, thus causing a denial of service.
    (CVE-2020-2100)

  - A non-constant time comparison of inbound TCP agent connection secret
    is used when an inbound TCP agent connection is initiated. This allows
    attackers to use statistical methods to obtain the connection secret.
    (CVE-2020-2101)

  - A non-constant time HMAC comparison is used when checking whether two
    HMACs are equal. This could potentially allow attackers to use
    statistical methods to obtain a valid HMAC for an attacker-controlled
    input value. (CVE-2020-2102)

  - User metadata on the /whoAmI page includes the HTTP session ID which
    allows attackers able to exploit a cross-site scripting vulnerability
    to obtain the HTTP session ID value. (CVE-2020-2103)

  - A lack of appropriate permissions allows anyone with Overall/Read
    permissions to access the JVM memory usage chart for the Jenkins master.
    (CVE-2020-2104)

  - The Jenkins REST APIs allows an attacker to perform a clickjacking
    attack by routing them to a specially crafted web page, and can expose
    the content of the REST API endpoint. (CVE-2020-2105)

Note that Nessus has not tested for these issues but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2020-01-29/");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins to version 2.219 or later, Jenkins LTS to version 2.204.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2105");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-2106");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Jenkins');

var constraints = [
  { 'fixed_version' : '2.219',    'fixed_display' : '2.204.2 LTS / 2.219',  'edition' : 'Open Source' },
  { 'fixed_version' : '2.204.2',  'fixed_display' : '2.204.2 LTS / 2.219',  'edition' : 'Open Source LTS' }
];

vcf::jenkins::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
