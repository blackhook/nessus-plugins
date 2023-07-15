#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc. 
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156227);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-43877");
  script_xref(name:"IAVA", value:"2021-A-0581-S");

  script_name(english:"Security Updates for Microsoft ASP.NET Core (December 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft ASP.NET Core installations on the remote host are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft ASP.NET Core installations on the remote host are missing a security update. It is, therefore,
affected by an elevation of privilege vulnerability. An attacker can exploit this to gain elevated privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/announcements/issues/206");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/aspnetcore/issues/39028");
  script_set_attribute(attribute:"solution", value:
"Update ASP.NET Core, remove vulnerable packages and refer to vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43877");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:asp.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_asp_dotnet_core_win.nbin");
  script_require_keys("installed_sw/ASP .NET Core Windows");

  exit(0);
}

include('vcf.inc');

var app = 'ASP .NET Core Windows';
var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'min_version' : '3.1',     'fixed_version' : '3.1.22' },
  { 'min_version' : '5.0',     'fixed_version' : '5.0.13' },
  { 'min_version' : '6.0',     'fixed_version' : '6.0.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
