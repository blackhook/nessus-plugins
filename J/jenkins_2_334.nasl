#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157860);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-43859", "CVE-2022-0538");

  script_name(english:"Jenkins LTS < 2.319.3 / Jenkins weekly < 2.334 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its its self-reported version number, the version of Jenkins running on the remote web server is Jenkins
LTS prior to 2.319.3 or Jenkins weekly prior to 2.334. It is, therefore, affected by multiple vulnerabilities:

  - XStream is an open source java library to serialize objects to XML and back again. Versions prior to
    1.4.19 may allow a remote attacker to allocate 100% CPU time on the target system depending on CPU type or
    parallel execution of such a payload resulting in a denial of service only by manipulating the processed
    input stream. XStream 1.4.19 monitors and accumulates the time it takes to add elements to collections and
    throws an exception if a set threshold is exceeded. Users are advised to upgrade as soon as possible.
    Users unable to upgrade may set the NO_REFERENCE mode to prevent recursion. See GHSA-rmr5-cpv2-vgjf for
    further details on a workaround if an upgrade is not possible. (CVE-2021-43859)

  - Jenkins 2.333 and earlier, LTS 2.319.2 and earlier defines custom XStream converters that have not been
    updated to apply the protections for the vulnerability CVE-2021-43859 and allow unconstrained resource
    usage. (CVE-2022-0538)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2022-02-09");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins weekly to version 2.334 or later or Jenkins LTS to version 2.319.3 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43859");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

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
  { 'max_version' : '2.333', 'fixed_version' : '2.334', 'edition' : 'Open Source' },
  { 'max_version' : '2.319.2', 'fixed_version' : '2.319.3', 'edition' : 'Open Source LTS' }
];

var app_info = vcf::combined_get_app_info(app:'Jenkins');

vcf::jenkins::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
