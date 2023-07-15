##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148360);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/13");

  script_cve_id(
    "CVE-2019-2392",
    "CVE-2019-20924",
    "CVE-2020-7921",
    "CVE-2020-7923",
    "CVE-2020-7925",
    "CVE-2020-7928",
    "CVE-2021-21533"
  );
  script_xref(name:"IAVB", value:"2021-B-0024");

  script_name(english:"Dell Wyse Management Suite < 3.2 Multiple Vulnerabilities (DSA-2021-070)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Dell Wyse Management Suite installed on the remote Windows host is affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Dell Wyse Management Suite installed on the remote Windows host is prior to 3.2. It is, therefore,
affected by multiple vulnerabilities, including the following:

  - Incorrect validation of user input in the role name parser may lead to use of uninitialized memory
    allowing an unauthenticated attacker to use a specially crafted request to cause a denial of service.
    This issue affects: MongoDB Inc. MongoDB Server v4.4 versions prior to 4.4.0-rc12; v4.2 versions prior to
    4.2.9. (CVE-2020-7925)

  - A user authorized to perform database queries may trigger a denial of service condition by issuing specially crafted
    queries which trigger an invariant in the IndexBoundsBuilder. This issue affects: MongoDB Inc. MongoDB
    Server v4.2 versions prior to 4.2.2 as used in Dell Wyse Management Suite. (CVE-2019-20924)

  - A user authorized to perform database queries may trigger a denial of service condition by issuing specially crafted
    queries, which use the $mod operator to overflow negative values. This issue affects: MongoDB Inc. MongoDB
    Server v4.4 versions prior to 4.4.1; v4.2 versions prior to 4.2.9; v4.0 versions prior to 4.0.20; v3.6
    versions prior to 3.6.20 as used in Dell Wyse Management Suite. (CVE-2019-2392)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-ie/000184666/dsa-2021-070-dell-wyse-management-suite-security-update-for-multiple-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f790118");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell Wyse Management Suite 3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7928");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:wyse_management_suite");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_wyse_management_suite_win_installed.nbin");
  script_require_keys("installed_sw/Dell Wyse Management Suite");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Dell Wyse Management Suite', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '3.2' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
