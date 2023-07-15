#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136566);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/08");

  script_cve_id("CVE-2020-1108");

  script_name(english:"Security Update for .NET Core SDK (May 2020)");
  script_summary(english:"Checks for Windows Install of .NET Core SDK.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a .NET Core SDK denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Core SDK installation on the remote host is
version 2.1.x < 2.1.514 or 2.1.611 or 2.1.806, or 3.1.x < 3.1.104 or
3.1.202. It is, therefore, affected by a denial of service
vulnerability due to an unspecified flaw related to handling web
requests. An unauthenticated, remote attacker could cause denial of
service conditions by sending specially crafted web requests.");
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

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dotnet_core_sdk_win.nbin");
  script_require_keys("installed_sw/.NET Core SDK Windows", "Settings/ParanoidReport");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = '.NET Core SDK Windows';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '2.1'    , 'fixed_version' : '2.1.514' },
  { 'min_version' : '2.1.600', 'fixed_version' : '2.1.611' },
  { 'min_version' : '2.1.800', 'fixed_version' : '2.1.806' },
  { 'min_version' : '3.1'    , 'fixed_version' : '3.1.104' },
  { 'min_version' : '3.1.200', 'fixed_version' : '3.1.202' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
