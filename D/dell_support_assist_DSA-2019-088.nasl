#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138150);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/09");

  script_cve_id("CVE-2019-3735");

  script_name(english:"Dell SupportAssist Improper Privilege Management Vulnerability (DSA-2019-088)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a Dell SupportAssist that is affected by an Improper Privilege Management Vulnerability.");
  script_set_attribute(attribute:"description", value:
"Dell SupportAssist for Business PCs version 2.0 and Dell SupportAssist for Home PCs version 
2.2, 2.2.1, 2.2.2, 2.2.3, 3.0, 3.0.1, 3.0.2, 3.1, 3.2, and 3.2.1 contain an Improper Privilege 
Management Vulnerability. A malicious local user can exploit this vulnerability by inheriting a 
system thread using a leaked thread handle to gain system privileges on the affected machine.");
  # https://www.dell.com/support/article/en-ie/sln317453/dsa-2019-088-dell-supportassist-security-update-for-improper-privilege-management-vulnerability?lang=en
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e92400d");
  script_set_attribute(attribute:"solution", value:
"Check vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3735");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/20");
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

constraints = [{'min_version': '2.2', 'fixed_version':'3.2.2'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
