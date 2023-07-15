##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161176);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/20");

  script_cve_id("CVE-2022-28834", "CVE-2022-28835", "CVE-2022-28836");
  script_xref(name:"IAVA", value:"2022-A-0209-S");

  script_name(english:"Adobe InCopy < 16.4.2 / 17.x < 17.2 Multiple Vulnerabilities (APSB22-28)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InCopy installed on the remote host is prior to version 16.4.2 or 17.x prior to 17.2.
It is, therefore, affected by multiple code execution vulnerabilities:

  - An out-of-bounds write flaw leading to an arbitrary code execution vulnerability. (CVE-2022-28834)

  - A use after free flaw leading to an arbitrary code execution vulnerability. (CVE-2022-28835)

  - An out-of-bounds write flaw leading to an arbitrary code execution vulnerability. (CVE-2022-28836)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/incopy/apsb22-28.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?245a5d41");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InCopy to 16.4.2, 17.42, or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28834");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:incopy");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_incopy_win_installed.nbin", "adobe_incopy_mac_installed.nbin");
  script_require_keys("installed_sw/Adobe InCopy");

  exit(0);
}

include('vcf.inc');

var app = 'Adobe InCopy';
var win_local;

if (!empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
  win_local = TRUE;
else
  win_local = FALSE;

var app_info = vcf::get_app_info(app:app, win_local:win_local);

var constraints = [
  {'fixed_version' : '16.4.2' },
  {'min_version': '17.0', 'fixed_version': '17.2'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
