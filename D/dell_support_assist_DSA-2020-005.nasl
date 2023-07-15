#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138151);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2020-5316");

  script_name(english:"Dell SupportAssist Uncontrolled Search Path Vulnerability (DSA-2020-005)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a Dell SupportAssist that is affected by an Uncontrolled Search Path Vulnerability.");
  script_set_attribute(attribute:"description", value:
"Dell SupportAssist for business PCs versions 2.0, 2.0.1, 2.0.2, 2.1, 2.1.1, 2.1.2, 2.1.3 
and Dell SupportAssist for home PCs version 2.0, 2.0.1, 2.0.2, 2.1, 2.1.1, 2.1.2, 2.1.3, 
2.2, 2.2.1, 2.2.2, 2.2.3, 3.0, 3.0.1, 3.0.2, 3.1, 3.2, 3.2.1, 3.2.2, 3.3, 3.3.1, 3.3.2, 
3.3.3, 3.4 contain an uncontrolled search path vulnerability. A locally authenticated low 
privileged user could exploit this vulnerability to cause the loading of arbitrary DLLs by 
the SupportAssist binaries, resulting in the privileged execution of arbitrary code.");
  # https://www.dell.com/support/article/en-ie/sln320101/dsa-2020-005-dell-supportassist-client-uncontrolled-search-path-vulnerability?lang=en
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cd5a579");
  script_set_attribute(attribute:"solution", value:
"Upgrade Dell SupportAssist Business Edition to version 2.1.4 or Home Edition to version 3.4.1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5316");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:supportassist");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_supportassist_installed.nbin");
  script_require_keys("installed_sw/Dell SupportAssist");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Dell SupportAssist', win_local:TRUE);

var dell_edition = tolower(app_info['Edition']);

if ('business' >< dell_edition)
  var constraints = [
    {'fixed_version':'2.1.4'}
  ]; 

else constraints = [{'fixed_version':'3.4.1'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
