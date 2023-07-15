##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(166250);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/20");

  script_cve_id("CVE-2022-42889");

  script_name(english:"Apache Commons Text 1.5.x < 1.10.0 Remote Code Execution (CVE-2022-42889)");

  script_set_attribute(attribute:"synopsis", value:
"A package installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Commons Text on the remote host is 1.5.x < 1.10.0. It is, therefore, affected by a remote code
execution vulnerability due to unsafe script evaluation in the StringSubstitutor default interpolator. 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://securitylab.github.com/advisories/GHSL-2022-018_Apache_Commons_Text/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?06368034");
  script_set_attribute(attribute:"see_also", value:"https://www.openwall.com/lists/oss-security/2022/10/13/4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Commons Text 1.10.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42889");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:commons_text");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_commons_text_jar_detect.nbin");
  script_require_keys("installed_sw/Apache Commons Text");

  exit(0);
}

include('vcf.inc');

var app = 'Apache Commons Text';

var app_info = vcf::get_app_info(app:app);

var constraints = [
  {'min_version':'1.5', 'fixed_version':'1.10.0'},
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);

