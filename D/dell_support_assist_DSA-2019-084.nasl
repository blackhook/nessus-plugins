#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138149);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/09");

  script_cve_id("CVE-2019-12280");

  script_name(english:"Dell SupportAssist PC Doctor Vulnerability (DSA-2019-084)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a Dell SupportAssist that is affected by a security vulnerability within the PC Doctor component.");
  script_set_attribute(attribute:"description", value:
"Dell SupportAssist for Business PCs version 2.0 and Dell SupportAssist for Home PCs version 
prior to 3.2.2 are affected  by a security vulnerability within the PC Doctor component 
(Uncontrolled Search Path Element before PC-Doctor Toolbox 7.3).");
  # https://www.dell.com/support/article/en-ie/sln317291/dsa-2019-084-dell-supportassist-for-business-pcs-and-dell-supportassist-for-home-pcs-security-update-for-pc-doctor-vulnerability?lang=en
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38b38d9a");
  script_set_attribute(attribute:"solution", value:
"Check vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12280");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:supportassist");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_supportassist_installed.nbin");
  script_require_keys("installed_sw/Dell SupportAssist");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Dell SupportAssist', win_local:TRUE);

constraints = [{'fixed_version':'3.2.2'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
