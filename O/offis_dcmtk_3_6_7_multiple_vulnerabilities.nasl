#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(162601);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-2119", "CVE-2022-2120", "CVE-2022-2121");

  script_name(english:"OFFIS DCMTK DICOM Toolkit < 3.6.7 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of OFFIS DCMTK DICOM Toolkit running on the remote server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of OFFIS DCMTK DICOM Toolkit hosted on the remote server
is affected by multiple vulnerabilities:

  - The affected product’s service class provider (SCP) is vulnerable to path
  traversal, allowing an attacker to write DICOM files into arbitrary
  directories under controlled names. This could allow remote code execution.
  (CVE-2022-2119)

  - The affected product’s service class user (SCU) is vulnerable to relative
  path traversal, allowing an attacker to write DICOM files into arbitrary
  directories under controlled names. This could allow remote code execution.
  (CVE-2022-2120)

  - The affected product has a NULL pointer dereference vulnerability while
  processing DICOM files, which may result in a denial-of-service condition.
  (CVE-2022-2121)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version");
  # https://www.cisa.gov/uscert/ics/advisories/icsma-22-174-01
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4522ca5d");
  # https://support.dcmtk.org/redmine/issues/1021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?45d16383");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OFFIS DCMTK DICOM Toolkit version referenced in the vendor security advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2120");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:offis:dcmtk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("offis_dcmtk_linux_installed.nbin", "offis_dcmtk_win_installed.nbin");
  script_require_keys("installed_sw/OFFIS DCMTK DICOM Toolkit");

  exit(0);
}

include('vcf.inc');

var win_local = FALSE;
if (!empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
  win_local = TRUE;

var app_info = vcf::get_app_info(app:'OFFIS DCMTK DICOM Toolkit', win_local:win_local);

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'fixed_version' : '3.6.7' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
