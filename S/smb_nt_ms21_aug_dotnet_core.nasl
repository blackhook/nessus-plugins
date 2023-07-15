#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152488);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/20");

  script_cve_id("CVE-2021-26423");
  script_xref(name:"IAVA", value:"2021-A-0379");

  script_name(english:"Security Update for .NET Core (August 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a .NET Core denial of service (DoS) vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Core installation on the remote host is version 2.1.x prior to 2.1.29, 3.1.x prior to 3.1.18, or 5.x
prior to 5.0.9.  It is, therefore affected by a denial of service (DoS) vulnerability, as server applications providing
WebSocket endpoints can be tricked into endlessly looping while trying to read a single WebSocket frame.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/2.1");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet-core/3.1");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/5.0");
  # https://github.com/dotnet/core/blob/main/release-notes/2.1/2.1.29/2.1.29.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ff12246");
  # https://github.com/dotnet/core/blob/main/release-notes/3.1/3.1.18/3.1.18.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0933ffe1");
  # https://github.com/dotnet/core/blob/main/release-notes/5.0/5.0.9/5.0.9.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6242d65f");
  script_set_attribute(attribute:"see_also", value:"https://devblogs.microsoft.com/dotnet/net-august-2021/");
  script_set_attribute(attribute:"solution", value:
"Update .NET Core, remove vulnerable packages and refer to vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26423");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_win.nbin");
  script_require_keys("installed_sw/.NET Core Windows");

  exit(0);
}

include('vcf.inc');

var app = '.NET Core Windows';
var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'min_version' : '2.1', 'fixed_version' : '2.1.29' },
  { 'min_version' : '3.1', 'fixed_version' : '3.1.18' },
  { 'min_version' : '5.0', 'fixed_version' : '5.0.9' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
