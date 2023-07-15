#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159895);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-2509");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/02");

  script_name(english:"QNAP QTS / QuTS hero Command Injection (QSA-21-05)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of QNAP QTS or QuTS hero on the remote host is affected by a command injection vulnerability. If exploited,
this vulnerability allows attackers to execute arbitrary commands in a compromised application. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qnap.com/en/security-advisory/qsa-21-05");
  script_set_attribute(attribute:"solution", value:
"Apply the workaround and upgrade to the relevant fixed version referenced in the QSA-21-05 advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2509");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:quts_hero");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qnap_qts_quts_hero_web_detect.nbin", "qnap_qts_installed.nbin");
  script_require_ports("installed_sw/QNAP QTS", "installed_sw/QNAP QuTS hero");

  exit(0);
}

include('vcf_extras_qnap.inc');

var app_info = vcf::qnap::get_app_info();

var constraints = [
  {'product':'QTS',       'min_version':'0.0',   'max_version':'4.2.6',                  'Build':'20210327', 'fixed_display':'QTS 4.2.6 build 20210327 '},
  {'product':'QTS',       'min_version':'4.3.3', 'max_version':'4.3.3', 'Number':'1624', 'Build':'20210416', 'fixed_display':'QTS 4.3.3.1624 build 20210416'},
  {'product':'QTS',       'min_version':'4.3.4', 'max_version':'4.3.4', 'Number':'1632', 'Build':'20210324', 'fixed_display':'QTS 4.3.4.1632 build 20210324'},
  {'product':'QTS',       'min_version':'4.3.6', 'max_version':'4.3.6', 'Number':'1620', 'Build':'20210322', 'fixed_display':'QTS 4.3.6.1620 build 20210322'},
  {'product':'QTS',       'min_version':'4.5.1', 'max_version':'4.5.1', 'Number':'1495', 'Build':'20201123', 'fixed_display':'QTS 4.5.1.1495 build 20201123'},
  {'product':'QTS',       'min_version':'4.5.2', 'max_version':'4.5.2', 'Number':'1566', 'Build':'20210202', 'fixed_display':'QTS 4.5.2.1566 build 20210202'},
  {'product':'QuTS hero', 'min_version':'0.0',   'max_version':'4.5.1', 'Number':'1491', 'Build':'20201119', 'fixed_display':'QuTS hero h4.5.1.1491 build 20201119'},
];

vcf::qnap::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
