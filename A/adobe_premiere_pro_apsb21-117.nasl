#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156223);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/22");

  script_cve_id(
    "CVE-2021-40790",
    "CVE-2021-40791",
    "CVE-2021-40795",
    "CVE-2021-42265",
    "CVE-2021-43751"
  );
  script_xref(name:"IAVA", value:"2021-A-0593");

  script_name(english:"Adobe Premiere Pro < 15.4.3/ 22.x < 22.1.1 Multiple Vulnerabilities (APSB21-117)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Premiere Pro installed on the remote host is prior to version 15.4.3 or 22.x prior to 22.1.1.
It is, therefore, affected by multiple vulnerabilities, including the following:

  - A use-after-free error that leads to a privilege escalation (CVE-2021-40790)

  - An out-of-bounds read error that leads to a privilege escalation (CVE-2021-40791)

  - An out-of-bounds read error that leads to arbitrary code execution (CVE-2021-40795)

  - An out-of-bounds read error that leads to a privilege escalation (CVE-2021-42265)

  - An out-of-bounds read error that leads to a privilege escalation (CVE-2021-43751)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/premiere_pro/apsb21-117.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d481839");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Premiere Pro to 15.4.3, 22.1.1, or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40795");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:premiere_pro");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:premiere_pro_cc");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_premiere_pro_installed.nasl", "macosx_adobe_premiere_pro_installed.nbin");
  script_require_ports("installed_sw/Adobe Premiere Pro");

  exit(0);
}

include('vcf.inc');

var app = 'Adobe Premiere Pro';
var win_local;

if (!empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
  win_local = TRUE;
else
  win_local = FALSE;

var app_info = vcf::get_app_info(app:app, win_local:win_local);

var constraints = [
  {'fixed_version' : '15.4.3' },
  {'min_version': '22', 'fixed_version': '22.1', 'fixed_display': '22.1.1'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
