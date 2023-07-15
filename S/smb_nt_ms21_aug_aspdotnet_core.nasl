#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152528);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-26423", "CVE-2021-34485", "CVE-2021-34532");
  script_xref(name:"IAVA", value:"2021-A-0378");

  script_name(english:"Security Update for Microsoft ASP.NET Core (August 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft ASP.NET Core installations on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft ASP.NET Core installation on the remote host is version 2.1.x prior to 2.1.29, 3.1.x prior to 3.1.18, or
5.x prior to 5.0.9. It is, therefore, affected by multiple vulnerabilities:

  - A denial of service (DoS) vulnerability. An attacker can exploit this issue to cause the affected 
    component to deny system or application services. (CVE-2021-26423)

  - An information disclosure vulnerability. An attacker can exploit this to disclose potentially sensitive
    information. (CVE-2021-34485, CVE-2021-34532)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet-core/2.1");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet-core/3.1");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/5.0");
  script_set_attribute(attribute:"see_also", value:"https://devblogs.microsoft.com/dotnet/net-august-2021");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/announcements/issues/194");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/announcements/issues/195");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/announcements/issues/196");
  # https://github.com/dotnet/core/blob/main/release-notes/2.1/2.1.30/2.1.30.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb1ce96e");
  # https://github.com/dotnet/core/blob/main/release-notes/3.1/3.1.18/3.1.18.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0933ffe1");
  # https://github.com/dotnet/core/blob/main/release-notes/5.0/5.0.9/5.0.9.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6242d65f");
  script_set_attribute(attribute:"solution", value:
"Update ASP.NET Core, remove vulnerable packages and refer to vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34532");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/12");

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
  { 'min_version' : '2.1',     'fixed_version' : '2.1.30' },
  { 'min_version' : '3.1',     'fixed_version' : '3.1.18' },
  { 'min_version' : '5.0',     'fixed_version' : '5.0.9' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
