#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(96657);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-3255");
  script_bugtraq_id(95543);

  script_name(english:"Oracle JDeveloper ADF Faces Unspecified Remote Information Disclosure (January 2017 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A software development application installed on the remote host is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JDeveloper installed on the remote host is
missing a security patch. It is, therefore, affected by an information
disclosure vulnerability in the Application Development Framework
(ADF) Faces subcomponent that allows an unauthenticated, remote
attacker to disclose arbitrary data.");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89a8e429");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2017 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3255");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdeveloper");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_jdeveloper_installed.nbin");
  script_require_keys("installed_sw/Oracle JDeveloper");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_jdev::get_app_info();

var constraints = [
  { 'min_version':'11.1.1.7', 'fixed_version':'11.1.1.7.161221', 'missing_patch':'25264940' },
  { 'min_version':'11.1.1.9', 'fixed_version':'11.1.1.9.170117', 'missing_patch':'25245227' },
  { 'min_version':'11.1.2.4', 'fixed_version':'11.1.2.4.170117', 'missing_patch':'25372028' },
  { 'min_version':'12.1.3.0', 'fixed_version':'12.1.3.0.170104', 'missing_patch':'25324374' },
  { 'min_version':'12.2.1.0', 'fixed_version':'12.2.1.0.170117', 'missing_patch':'25335432' },
  { 'min_version':'12.2.1.1', 'fixed_version':'12.2.1.1.170117', 'missing_patch':'25242617' },
  { 'min_version':'12.2.1.2', 'fixed_version':'12.2.1.2.170117', 'missing_patch':'23622699' }
];

vcf::oracle_jdev::check_version_and_report(
  app_info:app_info,
  severity:SECURITY_WARNING,
  constraints:constraints
);
