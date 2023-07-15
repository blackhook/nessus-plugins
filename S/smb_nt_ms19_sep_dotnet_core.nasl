#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128771);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-1301");
  script_xref(name:"IAVA", value:"2019-A-0328-S");

  script_name(english:"Security Update for .NET Core (Sep 2019)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a .NET Core denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Core installation on the remote host is version
2.1.x < 2.1.13, or 2.2.x < 2.2.7. It is, therefore, affected by a denial-of-service vulnerability
when .Net Core improperly handles web requests. An unauthenticated, remote attacker 
could exploit this issue, to cause a denial of service attack against
a .Net Core web application.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1301
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc33b45c");
  # https://github.com/dotnet/announcements/issues/121
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6437f9e");
  script_set_attribute(attribute:"solution", value:
"Refer to vendor documentation.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1301");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_asp_dotnet_core_win.nbin");
  script_require_keys("installed_sw/.NET Core SDK Windows", "Settings/ParanoidReport");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = '.NET Core Windows';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '2.1.0', 'fixed_version' : '2.1.13' },
  { 'min_version' : '2.2.0', 'fixed_version' : '2.2.7' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
