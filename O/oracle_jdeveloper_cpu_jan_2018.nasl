#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106903);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-10273", "CVE-2018-2711");
  script_bugtraq_id(102539, 102569);

  script_name(english:"Oracle JDeveloper Multiple Vulnerabilities (January 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A software development application installed on the remote host is
affected by a vulnerability which allows restricted path traversal 
due to improperly sanitized input as well as allowing the attacker
access to partially modify data");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JDeveloper installed on the remote host is
missing a security patch. Please see the vendor advisory for 
additional information.");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6072c657");
  # https://support.oracle.com/epmos/faces/DocumentDisplay?_afrLoop=398463191708425&id=2325393.1&_afrWindowMode=0&_adf.ctrl-state=13jjrzsqze_249
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2edd68c9");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2018 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2711");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdeveloper");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_jdeveloper_installed.nbin");
  script_require_keys("installed_sw/Oracle JDeveloper");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_jdev::get_app_info();

var constraints = [
  { 'min_version':'11.1.1.7', 'fixed_version':'11.1.1.7.171220', 'missing_patch':'27251436' },
  { 'min_version':'11.1.1.9', 'fixed_version':'11.1.1.9.171117', 'missing_patch':'27120730' },
  { 'min_version':'11.1.2.4', 'fixed_version':'11.1.2.4.171206', 'missing_patch':'27213077' },
  { 'min_version':'12.1.3.0', 'fixed_version':'12.1.3.0.171218', 'missing_patch':'27131743' },
  { 'min_version':'12.2.1.2', 'fixed_version':'12.2.1.2.171017', 'missing_patch':'26752344' }
];

vcf::oracle_jdev::check_version_and_report(
  app_info:app_info,
  severity:SECURITY_WARNING,
  constraints:constraints
);
