#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78911);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/07");

  script_cve_id("CVE-2014-6522");
  script_bugtraq_id(70472);

  script_name(english:"Oracle JDeveloper ADF Faces goButton XSS (October 2014 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A software development application installed on the remote host is
affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JDeveloper installed on the remote host is
missing a security patch. It is, therefore, affected by a cross-site
scripting (XSS) vulnerability in the Application Development Framework
(ADF) Faces subcomponent due to improper encoding of URLs that are
specified as a target for the 'goButton' component. An
unauthenticated, remote attacker can exploit this to execute arbitrary
script code in a user's browser session.");
  # https://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ada40cc");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/533701/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2014 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-6522");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdeveloper");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_jdeveloper_installed.nbin");
  script_require_keys("installed_sw/Oracle JDeveloper");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_jdev::get_app_info();

var constraints = [
  { 'min_version':'11.1.1.7', 'fixed_version':'11.1.1.7.141014', 'missing_patch':'19591065' },
  { 'min_version':'11.1.2.4', 'fixed_version':'11.1.2.4.141014', 'missing_patch':'19591073' },
  { 'min_version':'12.1.2.0', 'fixed_version':'12.1.2.0.141014', 'missing_patch':'19591074' },
  { 'min_version':'12.1.3.0', 'fixed_version':'12.1.3.0.141014', 'missing_patch':'19591087' }
];

vcf::oracle_jdev::check_version_and_report(
  app_info:app_info,
  severity:SECURITY_WARNING,
  constraints:constraints,
  flags:{'xss':TRUE}
);
