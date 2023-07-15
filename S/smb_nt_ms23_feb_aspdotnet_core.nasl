#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc. 
##

include('compat.inc');

if (description)
{
  script_id(171610);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/13");

  script_cve_id("CVE-2023-21808");
  script_xref(name:"IAVA", value:"2023-A-0091-S");

  script_name(english:"Security Updates for Microsoft ASP.NET Core (February 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft ASP.NET core installations on the remote host are affected by remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"A remote code execution vulnerability exists in ASP.NET Core 6.0 < 6.0.14 and ASP.NET Core 7.0 < 7.0.3. This
vulnerability exists due to how .NET reads debugging symbols, where reading a malicious symbols file may result
in remote code execution. An unauthenticated, local attacker can exploit this, to bypass authentication and execute
arbitrary commands.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/dotnet/core/blob/main/release-notes/6.0/6.0.14/6.0.14.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16cee765");
  # https://github.com/dotnet/core/blob/main/release-notes/7.0/7.0.3/7.0.3.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?523c1854");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/en-us/download/dotnet/6.0");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/en-us/download/dotnet/7.0");
  script_set_attribute(attribute:"solution", value:
"Update ASP.NET Core Runtime to version 6.0.14 or 7.0.3");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21808");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:asp.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_asp_dotnet_core_win.nbin");
  script_require_keys("installed_sw/ASP .NET Core Windows");

  exit(0);
}

include('vcf.inc');

var app = 'ASP .NET Core Windows';
var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  {'min_version': '6.0',  'fixed_version': '6.0.14'},
  {'min_version': '7.0',  'fixed_version': '7.0.3'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
