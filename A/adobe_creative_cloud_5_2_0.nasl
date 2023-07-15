#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138572);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/23");

  script_cve_id(
    "CVE-2020-9669",
    "CVE-2020-9670",
    "CVE-2020-9671",
    "CVE-2020-9682"
  );
  script_xref(name:"IAVA", value:"2020-A-0318");

  script_name(english:"Adobe Creative Cloud Desktop < 5.2 Multiple Vulnerabilities (APSB20-33)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Creative Cloud Desktop installed on the remote Windows host is prior to version 5.2. It is,
therefore, affected by the following vulnerabilities:

  - A lack of exploit mitigations that could lead to privilege escalation. (CVE-2020-9669)

  - Insecure file permissions that could lead to privilege escalation. (CVE-2020-9671)

  - A symlink vulnerability that could lead to privilege escalation. (CVE-2020-9670)

  - A symlink vulnerability that could lead to arbitrary file system write. (CVE-2020-9682)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/creative-cloud/apsb20-33.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4543dad2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Creative Cloud Desktop version 5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9682");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:creative_cloud");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_creative_cloud_installed.nbin");
  script_require_keys("installed_sw/Adobe Creative Cloud");

  exit(0);
}

include('vcf.inc');

app = 'Adobe Creative Cloud';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'fixed_version' : '5.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
