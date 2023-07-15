#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93592);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-3504", "CVE-2016-5019");
  script_bugtraq_id(92023, 93236);

  script_name(english:"Oracle JDeveloper Multiple RCE (July 2016 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A software development application installed on the remote host is
affected by multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JDeveloper installed on the remote host is
missing a security patch. It is, therefore, affected by multiple
remote code execution vulnerabilities :

  - A remote code execution vulnerability exists in the
    Application Development Framework (ADF) Faces
    subcomponent that allows an unauthenticated, remote
    attacker to execute arbitrary code. (CVE-2016-3504)

  - A remote code execution vulnerability exists in the
    Apache MyFaces Trinidad component in the
    CoreResponseStateManager subcomponent due to improper
    validation of the ObjectInputStream and
    ObjectOutputStream strings prior to deserialization. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2016-5019)");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?453b5f8c");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2016 Oracle Critical
Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5019");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdeveloper");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_jdeveloper_installed.nbin");
  script_require_keys("installed_sw/Oracle JDeveloper");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_jdev::get_app_info();

var constraints = [
  { 'min_version':'11.1.1.7', 'fixed_version':'11.1.1.7.160719', 'missing_patch':'23622763' },
  { 'min_version':'11.1.1.9', 'fixed_version':'11.1.1.9.150719', 'missing_patch':'23622640' },
  { 'min_version':'11.1.2.4', 'fixed_version':'11.1.2.4.160719', 'missing_patch':'23754328' },
  { 'min_version':'12.1.3.0', 'fixed_version':'12.1.3.0.160707', 'missing_patch':'23754311' },
  { 'min_version':'12.2.1.0', 'fixed_version':'12.2.1.0.160707', 'missing_patch':'23622699' }
];

vcf::oracle_jdev::check_version_and_report(
  app_info:app_info,
  severity:SECURITY_HOLE,
  constraints:constraints
);
