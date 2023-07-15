#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155865);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2021-44515");
  script_xref(name:"IAVA", value:"2021-A-0570-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/24");
  script_xref(name:"CEA-ID", value:"CEA-2021-0050");

  script_name(english:"ManageEngine Desktop Central < 10.1.2127.18 / 10.1.2128.0 < 10.1.2137.3 Authentication Bypass (CVE-2021-44515)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java-based web application that is affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The ManageEngine Desktop Central application running on the remote host is prior to 10.1.2127.18, or 10.1.2128.0 prior
to 10.1.2137.3. It is, therefore, affected by an authentication bypass vulnerability which can allow an adversary to
bypass authentication and execute arbitrary code in the Desktop Central server.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.manageengine.com/products/desktop-central/cve-2021-44515-authentication-bypass-filter-configuration.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa9e3175");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Desktop Central 10.1.2127.18 / 10.1.2137.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44515");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_desktop_central");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_desktop_central_installed.nbin");
  script_require_keys("installed_sw/ManageEngine Desktop Central");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'ManageEngine Desktop Central', win_local:TRUE);

var constraints = [
  {'fixed_version':'10.1.2127.18'},
  {'min_version':'10.1.2128.0', 'fixed_version':'10.1.2137.3'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
