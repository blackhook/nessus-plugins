#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174224);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/13");

  script_cve_id("CVE-2022-27597", "CVE-2022-27598");

  script_name(english:"QNAP QTS / QuTS hero Vulnerabilities in QTS, QuTS hero, QuTScloud, and QVP (QSA-23-06)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of QNAP QTS / QuTS hero installed on the remote host is affected by multiple vulnerabilities as referenced
in the QSA-23-06 advisory. A vulnerability have been reported to affect multiple QNAP operating systems. If exploited, 
the vulnerability allow remote authenticated users to get secret values. The vulnerabilities affect the following QNAP 
operating systems: QTS, QuTS hero, QuTScloud, QVP (QVR Pro appliances).

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qnap.com/en/security-advisory/QSA-23-06");
  script_set_attribute(attribute:"solution", value:
"Apply the solution referenced in the QSA-23-06 advisory");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27598");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:quts_hero");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qnap_qts_quts_hero_web_detect.nbin", "qnap_qts_installed.nbin", "qnap_quts_hero_installed.nbin");
  script_require_ports("installed_sw/QNAP QTS", "installed_sw/QNAP QuTS hero");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_qnap.inc');

var app_info = vcf::qnap::get_app_info();

var constraints = [
  {'product':'QTS',       'max_version':'5.0.1', 'Number':'2346', 'Build':'20230322', 'fixed_display':'QTS 5.0.1.2346 build 20230322'},
  {'product':'QuTS hero', 'max_version':'5.0.1', 'Number':'2348', 'Build':'20230324', 'fixed_display':'QuTS hero h5.0.1.2348 build 20230324'}
];
vcf::qnap::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
