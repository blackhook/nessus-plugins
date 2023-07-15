#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156790);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2021-44757");
  script_xref(name:"IAVA", value:"2022-A-0040");
  script_xref(name:"CEA-ID", value:"CEA-2022-0003");

  script_name(english:"ManageEngine Desktop Central < 10.1.2137.9 Authentication Bypass (CVE-2021-44757)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java-based web application that is affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The ManageEngine Desktop Central application running on the remote host is affected by an authentication bypass
vulnerability which allows an adversary to bypass authentication and read unauthorized data or write an arbitrary zip
file on the Desktop Central server.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://pitstop.manageengine.com/portal/en/community/topic/a-critical-security-patch-released-in-desktop-central-and-desktop-central-msp-for-cve-2021-44757-17-1-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?851289b8");
  # https://www.manageengine.com/products/desktop-central/cve-2021-44757.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0266c4d4");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44757");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_desktop_central");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_desktop_central_installed.nbin");
  script_require_keys("installed_sw/ManageEngine Desktop Central");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'ManageEngine Desktop Central', win_local:TRUE);

var constraints = [
  {'fixed_version':'10.1.2137.9'},
  {'min_version':'10.1.2140', 'fixed_version':'10.1.2150', 'fixed_display':'See vendor advisory'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
