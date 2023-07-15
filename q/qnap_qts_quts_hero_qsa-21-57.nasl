#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##
include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159512);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/05");

  script_name(english:"QNAP QTS / QuTS Hero Arbitrary Code Execution (QSA-21-57)");

  script_set_attribute(attribute:"synopsis", value:"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of QNAP QTS / QuTS Hero installed on the remote host is affected by an arbitrary code execution 
vulnerability. An unauthenticated, remote attacker can exploit this to bypass authentication and execute arbitrary
commands.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qnap.com/en/security-advisory/qsa-21-57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the QSA-21-57 advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of vulnerability");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:quts_hero");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qnap_qts_quts_hero_web_detect.nbin", "qnap_qts_installed.nbin");
  script_require_ports("installed_sw/QNAP QTS", "installed_sw/QNAP QuTS hero");

  exit(0);
}

include('vcf_extras_qnap.inc');

var app_info = vcf::qnap::get_app_info();

var constraints = [
  {'product':'QTS', 'min_version':'4.5.3', 'max_version':'4.5.4', 'Number':'1892', 'Build':'20211223', 'fixed_display':'QTS 4.5.4.1892 build 20211223'},
  {'product':'QTS', 'min_version':'5.0', 'max_version':'5.0.0', 'Number':'1891', 'Build':'20211221', 'fixed_display':'QTS 5.0.0.1891 build 20211221'},
  {'product':'QuTS hero', 'min_version':'4.5.3', 'max_version':'4.5.4', 'Number':'1892', 'Build':'20211223', 'fixed_display':'QuTS hero h4.5.4.1892 build 20211223'},
  {'product':'QuTS hero', 'min_version':'5.0', 'max_version':'5.0.0', 'Number':'1892', 'Build':'20211222', 'fixed_display':'QuTS hero h5.0.0.1892 build 20211222'}
];

vcf::qnap::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE
);
