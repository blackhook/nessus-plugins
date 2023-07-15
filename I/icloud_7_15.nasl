#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138080);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/14");

  script_cve_id(
    "CVE-2019-8783",
    "CVE-2019-8784",
    "CVE-2019-8811",
    "CVE-2019-8814",
    "CVE-2019-8815",
    "CVE-2019-8816",
    "CVE-2019-8819",
    "CVE-2019-8820",
    "CVE-2019-8821",
    "CVE-2019-8822",
    "CVE-2019-8823"
  );

  script_name(english:"Apple iCloud 7.x < 7.15 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An iCloud software installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the iCloud application installed on the remote Windows host is 7.x prior to 7.15. 
It is, therefore, affected by multiple vulnerabilities:

  - Multiple arbitrary code execution vulnerabilities exist with in the WebKit due to multiple memory 
    corruption issues. An unauthenticated, remote attacker can exploit this to execute arbitrary code. 
    (CVE-2019-8783, CVE-2019-8784, CVE-2019-8811, CVE-2019-8814, CVE-2019-8815, CVE-2019-8816, CVE-2019-8819,
    CVE-2019-8820, CVE-2019-8821, CVE-2019-8822, CVE-2019-8823)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/HT210728");
  script_set_attribute(attribute:"solution", value:
"Upgrade to iCloud version 7.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8816");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:icloud_for_windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("icloud_installed.nasl");
  script_require_keys("installed_sw/iCloud");

  exit(0);
}

include('vcf.inc');

app = 'iCloud';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  {'min_version' : '7.0',  'fixed_version' : '7.15'},
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
