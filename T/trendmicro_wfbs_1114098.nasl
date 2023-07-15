#
# (C) Tenable Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(134452);
  script_version("1.1");
  script_cvs_date("Date: 2020/03/13");

  script_name(english:"Trend Micro Worry-Free Business Security (WFBS) Multiple Vulnerabilities (1114098)");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running an application that is affected by 
  multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:"The remote host is running a version of the Trend Micro WFBS 
  which is affected by multiple vulnerabilities. An attacker who has already gained a foothold on the local WFBS server
  may manipulate configuration variables in order to access files outside of the web root folder or modify HTTP 
  response header values. Successful exploitation of the latter vulnerability may allow the attacker to conduct 
  additional attacks against the remote host.
  
  Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
  version.");
  # https://success.trendmicro.com/solution/1114098
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d79fff04");
  script_set_attribute(attribute:"solution", value:"Upgrade to the relevant fixed version referenced in Trend Micro 
  advisory 1114098");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on analysis of vendor advisory");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("trendmicro_server_win_installed.nbin");
  script_require_keys("installed_sw/Trend Micro Worry-Free Business Security Advanced");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Trend Micro Worry-Free Business Security Advanced');
vcf::check_granularity(app_info:app_info, sig_segments:4);

constraints = [
  {'min_version':'8.0.0', 'max_version':'8.0.0.2084', 'fixed_version':'8.0.0.2090'},
  {'min_version':'9.0.0', 'max_version':'9.0.0.4047', 'fixed_version':'9.0.0.4060'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
