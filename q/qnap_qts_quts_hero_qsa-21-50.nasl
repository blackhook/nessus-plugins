#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159577);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/12");

  script_name(english:"QNAP QTS / QuTS hero Buffer Overflow (QSA-21-50)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of QNAP QTS or QuTS hero on the remote host is affected by a heap-based buffer overflow vulnerability in
devices that have Apple File Protocol (AFP) enabled. This allows attackers to execute arbitrary code.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qnap.com/en/security-advisory/qsa-21-50");
  script_set_attribute(attribute:"solution", value:
"Apply the workaround and upgrade to the relevant fixed version referenced in the QSA-21-50 advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"score from a more in depth analysis done by Tenable");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:quts_hero");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qnap_qts_quts_hero_web_detect.nbin", "qnap_qts_installed.nbin");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("installed_sw/QNAP QTS", "installed_sw/QNAP QuTS hero");

  exit(0);
}

include('vcf_extras_qnap.inc');

var app_info = vcf::qnap::get_app_info();

# Not checking for AFP
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'product':'QTS',       'min_version':'0.0',   'max_version':'4.3.3', 'Number':'1799', 'Build':'20211008', 'fixed_display':'QTS 4.3.3.1799 build 20211008'},
  {'product':'QTS',       'min_version':'4.3.6', 'max_version':'4.3.6', 'Number':'1831', 'Build':'20211019', 'fixed_display':'QTS 4.3.6.1831 build 20211019'},
  {'product':'QTS',       'min_version':'4.5.4', 'max_version':'4.5.4', 'Number':'1800', 'Build':'20210923', 'fixed_display':'QTS 4.5.4.1800 build 20210923'},
  {'product':'QTS',       'min_version':'5.0.0', 'max_version':'5.0.0', 'Number':'1808', 'Build':'20211001', 'fixed_display':'QTS 5.0.0.1808 build 20211001'},
  {'product':'QuTS hero', 'min_version':'0.0',   'max_version':'4.5.4', 'Number':'1813', 'Build':'20211006', 'fixed_display':'QuTS hero h4.5.4.1813 build 20211006'},
  {'product':'QuTS hero', 'min_version':'5.0.0', 'max_version':'5.0.0', 'Number':'1844', 'Build':'20211105', 'fixed_display':'QuTS hero 5.0.0.1844 build 20211105'}
];

vcf::qnap::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
