#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156229);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/22");

  script_cve_id(
    "CVE-2021-40783",
    "CVE-2021-40784",
    "CVE-2021-43021",
    "CVE-2021-43022",
    "CVE-2021-43023",
    "CVE-2021-43024",
    "CVE-2021-43025",
    "CVE-2021-43026",
    "CVE-2021-43028",
    "CVE-2021-43029",
    "CVE-2021-43030",
    "CVE-2021-43746",
    "CVE-2021-43747",
    "CVE-2021-43748",
    "CVE-2021-43749",
    "CVE-2021-43750"
  );
  script_xref(name:"IAVA", value:"2021-A-0594");

  script_name(english:"Adobe Premiere Rush <= 1.5.16 Multiple Vulnerabilities (APSB21-101)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Premiere Rush installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Premiere Rush installed on the remote Windows host is version less than or equal to 1.5.16. It is,
therefore, affected by multiple vulnerabilities, including the following:

  - Arbitrary code execution vulnerabilities caused by accessing memory locations after the end of a buffer.
    (CVE-2021-40783, CVE-2021-40784, CVE-2021-43021, CVE-2021-43022, CVE-2021-43023, CVE-2021-43025,
    CVE-2021-43026, CVE-2021-43028, CVE-2021-43029, CVE-2021-43747)

  - Privilege escalation caused by access of an uninitialized pointer. (CVE-2021-43030)

  - Application denial of service caused by access of a memory location after the end of a buffer.
    (CVE-2021-43024)

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  # https://helpx.adobe.com/security/products/premiere_rush/apsb21-101.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d8e6261");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Premiere Rush version 2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43747");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:premiere_rush");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_premiere_rush_installed.nasl");
  script_require_keys("installed_sw/Adobe Premiere Rush", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Adobe Premiere Rush', win_local:TRUE);

constraints = [
  { 'fixed_version' : '1.5.17', 'fixed_display' : '2.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
