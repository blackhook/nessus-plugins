##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160542);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-28799");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/21");

  script_name(english:"QNAP QTS / QuTS hero Improper Authorization Vulnerability in HBS 3 (QSA-21-13)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of QNAP QTS or QuTS hero on the remote host is affected by an improper authorization vulnerability when
running HBS 3 (Hybrid Backup Sync).  If exploited, the vulnerability allows remote attackers to log in to a device.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qnap.com/en/security-advisory/qsa-21-13");
  script_set_attribute(attribute:"solution", value:
"Apply the workaround and upgrade to the relevant fixed version referenced in the QSA-21-13 advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28799");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:quts_hero");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qnap_qts_quts_hero_web_detect.nbin", "qnap_qts_installed.nbin");
  script_require_keys("installed_sw/QNAP QTS", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_qnap.inc');

var app_info = vcf::qnap::get_app_info();

# not checking HBS version
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'product':'QTS',       'min_version':'4.5.2',   'fixed_version':'4.5.3', 'fixed_display':'See vendor advisory'},
  {'product':'QTS',       'min_version':'4.3.3',   'fixed_version':'4.3.5', 'fixed_display':'See vendor advisory'},
  {'product':'QTS',       'min_version':'4.3.6',   'fixed_version':'4.3.7', 'fixed_display':'See vendor advisory'},
  {'product':'QuTS hero', 'min_version':'4.5.1',   'fixed_version':'4.5.2', 'fixed_display':'See vendor advisory'}
];

vcf::qnap::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
