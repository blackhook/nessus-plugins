#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84881);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2015-4742");
  script_bugtraq_id(75841);

  script_name(english:"Oracle JDeveloper ADF Faces DoS (July 2015 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A software development application installed on the remote host is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JDeveloper installed on the remote host is
missing a security patch. It is, therefore, affected by an unspecified
flaw in the Application Development Framework (ADF) Faces subcomponent
that allows an unauthenticated, remote attacker to cause a denial of
service condition.");
  # https://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f2b7623c");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2015 Oracle Critical
Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4742");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdeveloper");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_jdeveloper_installed.nbin");
  script_require_keys("installed_sw/Oracle JDeveloper");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_jdev::get_app_info();

var constraints = [
  { 'min_version':'11.1.1.7', 'fixed_version':'11.1.1.7.150723', 'missing_patch':'20715966' },
  { 'min_version':'11.1.2.4', 'fixed_version':'11.1.2.4.150709', 'missing_patch':'20715992' },
  { 'min_version':'12.1.2.0', 'fixed_version':'12.1.2.0.150709', 'missing_patch':'20716002' },
  { 'min_version':'12.1.3.0', 'fixed_version':'12.1.3.0.150715', 'missing_patch':'20716006' }
];

vcf::oracle_jdev::check_version_and_report(
  app_info:app_info,
  severity:SECURITY_WARNING,
  constraints:constraints
);
