#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154961);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-36741", "CVE-2021-36742");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"Trend Micro Worry-Free Business Security (WFBS) 10.0 SP1 < 10.0 SP1 Patch 2329 Multiple Vulnerabilities (000287820)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Trend Micro WFBS  running on the remote Windows host is 10.0 SP1
prior to patch 2329. It is, therefore, affected by multiple vulnerabilities:
 
 - An improper input validation vulnerability in Trend Micro Worry-Free Business Security 10.0 SP1 allows 
   a remote attached to upload arbitrary files on affected installations. (CVE-2021-36741)

 - An improper input validation vulnerability in Trend Micro Worry-Free Business Security 10.0 SP1 allows 
   a local attacker to escalate privileges on affected installations. (CVE-2021-36742)

   Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
   version number.");
  # https://success.trendmicro.com/solution/000287820
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ccfa96f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 10.0 SP1 Patch 2329 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36741");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("trendmicro_server_win_installed.nbin");
  script_require_keys("installed_sw/Trend Micro Worry-Free Business Security Advanced");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Trend Micro Worry-Free Business Security Advanced');
vcf::check_granularity(app_info:app_info, sig_segments:4);

var constraints = [
  {'min_version':'10.0.0', 'fixed_version':'10.0.0.2329'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
