#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177105);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/13");

  script_cve_id("CVE-2020-25840", "CVE-2021-22506");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"Micro Focus Access Manager < 5.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The Micro Focus Access Manager instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Micro Focus Access Manager installed on the remote host is prior to 5.0. It is, therefore, affected by
the following vulnerabilities:

  - Cross-Site scripting vulnerability in Micro Focus Access Manager product, affects all version prior to version 5.0. The vulnerability could cause configuration destruction. (CVE-2020-25840)

  - Advance configuration exposing Information Leakage vulnerability in Micro Focus Access Manager product, affects all versions prior to version 5.0. The vulnerability could cause information leakage. (CVE-2021-22506)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.microfocus.com/documentation/access-manager/5.0/accessmanager50-release-notes/accessmanager50-release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84aa819e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Micro Focus Access Manager version 5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22506");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microfocus:netiq_access_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microfocus_netiq_access_manager_nix_installed.nbin", "microfocus_netiq_access_manager_win_installed.nbin");
  script_require_keys("installed_sw/Micro Focus NetIQ Access Manager");

  exit(0);
}

include('vcf.inc');

var app = 'Micro Focus NetIQ Access Manager';
var win_local = FALSE;
if (!empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
  win_local = TRUE;

var app_info = vcf::get_app_info(app:app, win_local:win_local);

var constraints = [
  { 'fixed_version' : '5.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
