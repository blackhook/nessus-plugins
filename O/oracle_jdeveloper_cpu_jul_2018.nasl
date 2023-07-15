#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111332);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2015-7940");
  script_bugtraq_id(79091);

  script_name(english:"Oracle JDeveloper Information Disclosure Vulnerability (July 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A software development application installed on the remote host is
affected by an information disclosure vulnerability within the Bouncy
Castle Java package");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JDeveloper installed on the remote host is
missing a security patch. Please see the vendor advisory for 
additional information.");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60bcb092");
  # https://support.oracle.com/rs?type=doc&id=2394520.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19cc26a6");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2018 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7940");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/25");

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
  { 'min_version':'12.1.3.0', 'fixed_version':'12.1.3.0.180525', 'missing_patch':'27800100' },
  { 'min_version':'12.2.1.2', 'fixed_version':'12.2.1.2.180525', 'missing_patch':'27783350' },
  { 'min_version':'12.2.1.3', 'fixed_version':'12.2.1.3.180607', 'missing_patch':'28151020' }
  # Note: 27957723 appears to be the original patch for 12.2.1.3, but is no longer listed
];

vcf::oracle_jdev::check_version_and_report(
  app_info:app_info,
  severity:SECURITY_WARNING,
  constraints:constraints
);
