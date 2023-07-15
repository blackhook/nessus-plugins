#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136565);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/11");

  script_cve_id("CVE-2020-1108");
  script_xref(name:"IAVA", value:"2020-A-0200-S");

  script_name(english:"Security Update for .NET Core (May 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a .NET Core denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Core installation on the remote host is version
2.1.x < 2.1.18 or 3.1.x < 3.1.4. It is, therefore, affected by a
denial of service vulnerability due to an unspecified flaw related to
handling web requests. An unauthenticated, remote attacker could cause
denial of service conditions by sending specially crafted web
requests.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1108
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?9fce9442");
  script_set_attribute(attribute:"see_also", value:"https://github.com/dotnet/announcements/issues/156");
  script_set_attribute(attribute:"solution", value:
"Refer to vendor documentation.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1108");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_win.nbin");
  script_require_keys("installed_sw/.NET Core Windows");

  exit(0);
}

include('vcf.inc');

app = '.NET Core Windows';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '2.1.0', 'fixed_version' : '2.1.18' },
  { 'min_version' : '3.1.0', 'fixed_version' : '3.1.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
