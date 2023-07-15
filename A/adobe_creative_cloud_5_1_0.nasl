#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134945);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/17");

  script_cve_id("CVE-2020-3808");
  script_xref(name:"IAVA", value:"2020-A-0116-S");

  script_name(english:"Adobe Creative Cloud Desktop < 5.1.0.407 Arbitrary File Deletion Vulnerability (APSB20-11)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by an arbitrary file deletion vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Creative Cloud Desktop installed on the remote Windows host is equal prior to 5.1.0.407. It is,
therefore, affected by a time-of-check to time-of-use (TOCTOU) race condition. An attacker could exploit this to
delete arbitrary files.");
  # https://helpx.adobe.com/security/products/creative-cloud/apsb20-11.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10db490c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Creative Cloud Desktop version 5.0.1.407 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3808");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/27");

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
  { 'fixed_version' : '5.0.1.407' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
