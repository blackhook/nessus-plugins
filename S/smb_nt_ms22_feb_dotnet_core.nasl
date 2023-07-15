#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc. 
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157879);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id("CVE-2022-21986");
  script_xref(name:"IAVA", value:"2022-A-0078-S");

  script_name(english:"Security Update for .NET Core (February 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET core installations on the remote host are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET core installation on the remote host is version 5.0 prior to 5.0.14 or version 6.0 prior to 6.0.2.
It is, therefore, affected by a denial of service (DoS) vulnerability. An attacker can exploit this issue to cause
the affected component to deny system or application services.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/5.0");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/6.0");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/announcements/issues/208");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21986
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?65bd7b62");
  script_set_attribute(attribute:"solution", value:
"Update to .NET Core Runtime to version 5.0.14 or 6.0.2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21986");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_win.nbin");
  script_require_keys("installed_sw/.NET Core Windows");

  exit(0);
}

include('vcf.inc');

var app = '.NET Core Windows';
var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'min_version' : '5.0', 'fixed_version' : '5.0.14' },
  { 'min_version' : '6.0', 'fixed_version' : '6.0.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);


