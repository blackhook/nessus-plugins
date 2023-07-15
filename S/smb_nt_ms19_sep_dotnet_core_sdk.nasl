#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(128772);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2019-1301", "CVE-2019-1302");
  script_xref(name:"IAVA", value:"2019-A-0328-S");

  script_name(english:"Security Update for .NET Core SDK (Sep 2019)");
  script_summary(english:"Checks for Windows Install of .NET Core.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple .NET Core SDK vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft .NET Core SDK installation on the remote host is version
2.1.x < 2.1.509, or 2.1.606 or 2.1.802, 2.2.x < 2.2.109 or 2.2.206 or 2.2.302.
It is, therefore, affected by multiple vulnerabilities: 

  - A denial of service vulnerability when .Net Core improperly handles 
    web requests. An unauthenticated, remote attacker 
    could exploit this issue, to cause a denial of service attack against
    a .Net Core web application. (CVE-2019-1301)

  - An elevation of privilege vulnerability that could lead to 
    a content injection attack enabling an attacker to run a script 
    in the context of the logged-on user. An unauthenticated, remote attacker 
    could exploit this issue, via a link that has a specially crafted URL,
    and convince the user to click the link. (CVE-2019-1302)");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1301
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc33b45c");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1302
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?729669e9");
  # https://github.com/aspnet/Announcements/issues/384
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40f974ac");
  # https://github.com/aspnet/AspNetCore/issues/13859
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5164378b");
  # https://github.com/dotnet/announcements/issues/121
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6437f9e");
  script_set_attribute(attribute:"solution", value:
"Refer to vendor documentation.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1302");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '2.1', 'fixed_version' : '2.1.509' },
  { 'min_version' : '2.1.600', 'fixed_version' : '2.1.606'},
  { 'min_version' : '2.1.700', 'fixed_version' : '2.1.802'},
  { 'min_version' : '2.2', 'fixed_version' : '2.2.109' },
  { 'min_version' : '2.2.200', 'fixed_version' : '2.2.206'},
  { 'min_version' : '2.2.300', 'fixed_version' : '2.2.402'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
