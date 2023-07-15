#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160335);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2022-26871");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/21");

  script_name(english:"Trend Micro Apex Central RCE (000290678)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is running an application that is affected by an remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Trend Micro application running on the remote Windows host is Apex Central
prior to patch 3 build 6016. It is, therefore, affected by an arbitrary file upload vulnerability. An unauthenticated,
remote attacker could exploit this to upload arbitrary files to an affected host. Successful exploitation of this 
vulnerability could result in arbitrary code execution.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://success.trendmicro.com/dcx/s/solution/000290678");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Trend Micro Apex Central patch 3 build 6016 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26871");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trendmicro:apex_central");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("trendmicro_apex_central_win_installed.nbin");
  script_require_keys("installed_sw/Trend Micro Apex Central");

  exit(0);
}

include('vcf_extras_trendmicro.inc');

var app_info = vcf::trendmicro::apex_central::get_app_info();

var constraints = [{'fixed_version': '6016', 'fixed_display': '2019 Build 6016 Patch 3'}];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE
);
