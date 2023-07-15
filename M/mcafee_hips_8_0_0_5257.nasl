#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(152041);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/27");

  script_cve_id("CVE-2020-7279");
  script_xref(name:"IAVA", value:"2020-A-0108");

  script_name(english:"McAfee Host Intrusion Prevention Services < 8.0.0.5257 DLL Search Order Hijacking (SB10320)");

  script_set_attribute(attribute:"synopsis", value:
"A security application installed on the remote host is affected by a DLL search order hijacking vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee Host Intrusion Prevention Services (HIPS) is prior to 8.0.0.5257. It is, therefore, affected by
a DLL search order hijacking vulnerability. It allows attackers with local access to execute arbitrary code via
execution from a compromised folder.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10320");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=KB56057");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Host Intrusion Prevention Services 8.0 Patch 15 (8.0.0.5257) or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7279");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:host_intrusion_prevention");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_hips_installed.nbin");
  script_require_keys("installed_sw/McAfee Host Intrusion Prevention");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'McAfee Host Intrusion Prevention', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

# all prior to 8.0 Patch 15 (from firesvc.exe file version and other files)
var constraints = [
  { 'min_version' : '1.0.0.0', 'fixed_version' : '8.0.0.5257'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

