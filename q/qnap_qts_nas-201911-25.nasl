##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162318);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/12");

  script_cve_id(
    "CVE-2019-7192",
    "CVE-2019-7193",
    "CVE-2019-7194",
    "CVE-2019-7195"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"QNAP QTS 4.3.6 < 4.3.6 build 20190919 / 4.4.1 < 4.4.1 build 20190918 Multiple Vulnerabilities (NAS-201911-25)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of QNAP QTS installed on the remote host is affected by multiple vulnerabilities, as follows:

  - An improper input validation vulnerability that allows remote attackers to inject arbitrary code to the
    system. (CVE-2019-7193)

  - Two external control of file name or path vulnerabilities that allow remote attackers to access or modify
    system files. (CVE-2019-7195, CVE-2019-7194)

  - An improper access control vulnerability that allows remote attackers to gain unauthorized access to the
    system. (CVE-2019-7192)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qnap.com/zh-tw/security-advisory/nas-201911-25");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the NAS-201911-25 advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7193");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-7195");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:qts");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qnap_qts_quts_hero_web_detect.nbin", "qnap_qts_installed.nbin");
  script_require_ports("installed_sw/QNAP QTS");

  exit(0);
}

include('vcf_extras_qnap.inc');

var app_info = vcf::qnap::get_app_info();

var constraints = [
  {'product':'QTS', 'min_version':'4.4.1', 'max_version':'4.4.1', 'Number':'1064', 'Build':'20190918', 'fixed_display':'QTS 4.4.1: build 20190918'},
  {'product':'QTS', 'min_version':'4.3.6', 'max_version':'4.3.6', 'Number':'1070', 'Build':'20190919', 'fixed_display':'QTS 4.3.6: build 20190919'}
];

vcf::qnap::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
