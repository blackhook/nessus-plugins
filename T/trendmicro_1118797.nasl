#
# (C) Tenable Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(134892);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/24");

  script_name(english:"Trend Micro Malware Sample Detection Bypass Vulnerability (1118797)");

  script_set_attribute(attribute:"synopsis", value:
  "The remote host is running an antivirus engine appication with an outdated pattern file");
  script_set_attribute(attribute:"description", value:
  "The remote host is running a version of the Trend Micro engine with an outdated pattern file. It is, therefore,
  affected by an issue whereby certain malware samples may, incorrectly, be classified as benign.");
  # https://success.trendmicro.com/solution/1118797
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?775a6618");
  script_set_attribute(attribute:"solution", value:"Upgrade Trend Micro pattern file to version 13.765.00 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of vendor advisory");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trend_micro:trend_micro_antivirus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("trendmicro_installed.nasl");
  script_require_keys("Antivirus/TrendMicro/installed", "Antivirus/TrendMicro/trendmicro_internal_pattern_display_version");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(
  app:'TrendMicro',
  kb_ver:'Antivirus/TrendMicro/trendmicro_internal_pattern_display_version',
  win_local:TRUE
);

constraints = [{ 'fixed_version' : '13.765.00' }];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
