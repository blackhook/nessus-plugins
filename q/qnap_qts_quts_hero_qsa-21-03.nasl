#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159568);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/12");

  script_cve_id("CVE-2018-19957");

  script_name(english:"QNAP QTS / QuTS hero Insufficient HTTP Security Headers (QSA-21-03)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of QNAP QTS or QuTS hero on the remote host is affected by a vulnerability involving insufficient HTTP
security headers. This vulnerability allows remote attackers to launch privacy and security attacks.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qnap.com/en/security-advisory/qsa-21-03");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the QSA-21-03 advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19957");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/07");

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
  {'product':'QTS',       'max_version':'4.5.4', 'Number':'1715', 'Build':'20210630', 'fixed_display':'QTS 4.5.4.1715 build 20210630'},
  {'product':'QuTS hero', 'max_version':'4.5.4', 'Number':'1771', 'Build':'20210825', 'fixed_display':'QuTS hero h4.5.4.1771 build 20210825'}
];

vcf::qnap::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
