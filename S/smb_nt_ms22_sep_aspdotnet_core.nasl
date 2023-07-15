#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc. 
##

include('compat.inc');

if (description)
{
  script_id(165076);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/30");

  script_cve_id("CVE-2022-38013");
  script_xref(name:"MSKB", value:"5017903");
  script_xref(name:"MSKB", value:"5017915");
  script_xref(name:"MSFT", value:"MS22-5017903");
  script_xref(name:"MSFT", value:"MS22-5017915");
  script_xref(name:"IAVA", value:"2022-A-0374-S");

  script_name(english:"Security Updates for Microsoft ASP.NET Core (September 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft ASP.NET Core installations on the remote host are missing a security update.");
  script_set_attribute(attribute:"description", value:
"A denial of service vulnerability exists in ASP.NET core 6.0 < 6.0.9 and ASP.NET Core 3.1 < 3.1.29. An unauthenticated,
remote attacker can exploit this, by sending a customized payload that is parsed during model binding, to cause a stack
overflow, which may cause the application to stop responding.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/announcements/issues/234");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-38013
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c76821a3");
  script_set_attribute(attribute:"solution", value:
"Update ASP.NET Core Runtime to version 3.1.29 or 6.0.9.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38013");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:asp.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_asp_dotnet_core_win.nbin");
  script_require_keys("installed_sw/ASP .NET Core Windows");

  exit(0);
}

include('vcf.inc');

var app = 'ASP .NET Core Windows';
var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  {'min_version': '3.1', 'fixed_version': '3.1.29'},
  {'min_version': '6.0', 'fixed_version': '6.0.9'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
