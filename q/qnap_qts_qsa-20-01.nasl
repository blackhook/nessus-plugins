##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161596);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-19943", "CVE-2018-19949", "CVE-2018-19953");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/14");

  script_name(english:"QNAP QTS Multiple Vulnerabilities in File Station (QSA-20-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of QNAP QTS installed on the remote host is affected by multiple vulnerabilities, as follows:

  - A vulnerability that allows remote attackers to run arbitrary commands. (CVE-2018-19949)

  - Two cross-site scripting (XSS) vulnerabilities that allow remote attackers to inject malicious code.
    (CVE-2018-19943, CVE-2018-19953)


Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qnap.com/en/security-advisory/qsa-20-01");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the QSA-20-01 advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19949");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:qts");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qnap_qts_quts_hero_web_detect.nbin", "qnap_qts_installed.nbin");
  script_require_keys("installed_sw/QNAP QTS");

  exit(0);
}

include('vcf_extras_qnap.inc');

var app_info = vcf::qnap::get_app_info();

var constraints = [
  {'product':'QTS',                        'max_version':'4.2.6',                  'Build':'20200421', 'fixed_display':'QTS 4.2.6 build 20200421'},
  {'product':'QTS', 'min_version':'4.3.3', 'max_version':'4.3.3', 'Number':'1252', 'Build':'20200409', 'fixed_display':'QTS 4.3.3.1252 build 20200409'},
  {'product':'QTS', 'min_version':'4.3.4', 'max_version':'4.3.4', 'Number':'1282', 'Build':'20200408', 'fixed_display':'QTS 4.3.4.1282 build 20200408'},
  {'product':'QTS', 'min_version':'4.3.6', 'max_version':'4.3.6', 'Number':'1263', 'Build':'20200330', 'fixed_display':'QTS 4.3.6.1263 build 20200330'},
  {'product':'QTS', 'min_version':'4.4.1', 'max_version':'4.4.1', 'Number':'1261', 'Build':'20200330', 'fixed_display':'QTS 4.4.1.1261 build 20200330'},
  {'product':'QTS', 'min_version':'4.4.2', 'max_version':'4.4.2', 'Number':'1270', 'Build':'20200410', 'fixed_display':'QTS 4.4.2.1270 build 20200410'},
];

vcf::qnap::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{'xss':TRUE}
);
