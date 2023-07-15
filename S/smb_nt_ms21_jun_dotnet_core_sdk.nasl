#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150365);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/12");

  script_cve_id("CVE-2021-31957");
  script_xref(name:"IAVA", value:"2021-A-0274-S");

  script_name(english:"Security Update for .NET Core SDK (June 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a .NET Core SDK denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Core SDK installation on the remote host is version 3.1.x prior to 3.1.116, 3.1.2xx prior to
3.1.410, 5.x prior to 5.0.204, or 5.0.3xx prior to 5.0.301. It is, therefore, affected by a denial of service
vulnerability. An unauthenticated, remote attacker can exploit this to cause the application to stop responding.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet-core/3.1");
  script_set_attribute(attribute:"see_also", value:"https://dotnet.microsoft.com/download/dotnet/5.0");
  # https://github.com/dotnet/core/blob/main/release-notes/3.1/3.1.16/3.1.16.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf839a13");
  # https://github.com/dotnet/core/blob/main/release-notes/5.0/5.0.7/5.0.7.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c41b94c");
  script_set_attribute(attribute:"solution", value:
"Update .NET Core SDK, remove vulnerable packages and refer to vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31957");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_sdk_win.nbin");
  script_require_keys("installed_sw/.NET Core SDK Windows");

  exit(0);
}

include('vcf.inc');

app = '.NET Core SDK Windows';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '3.1',     'fixed_version' : '3.1.116' },
  { 'min_version' : '3.1.200', 'fixed_version' : '3.1.410' },
  { 'min_version' : '5.0',     'fixed_version' : '5.0.204' },
  { 'min_version' : '5.0.300', 'fixed_version' : '5.0.301' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
