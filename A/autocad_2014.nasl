#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73291);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/02");

  script_cve_id("CVE-2014-0818", "CVE-2014-0819");

  script_name(english:"Autodesk AutoCAD < 2014 Multiple Vulnerabilities");
  
  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Autodesk AutoCAD installed prior to
AutoCAD 2014. It is, therefore, potentially affected by the following
vulnerabilities :

  - An error exists related to handling FAS files that
    could allow execution of arbitrary VBScript code.
    (CVE-2014-0818)

  - An error exists related to dynamic library loading.
    The application insecurely looks in the current working
    directory when resolving DLL dependencies. Attackers may
    exploit the issue by placing a specially crafted DLL
    file and another file associated with the application in
    a location controlled by the attacker. When the
    associated file is launched, the attacker's arbitrary
    code can be executed. (CVE-2014-0819)");
  script_set_attribute(attribute:"see_also", value:"http://jvn.jp/en/jp/JVN43254599/index.html");
  script_set_attribute(attribute:"see_also", value:"http://jvn.jp/en/jp/JVN33382534/index.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Autodesk AutoCAD 2014 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0818");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("autocad_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Autodesk AutoCAD");

  exit(0);

}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Autodesk AutoCAD', win_local:TRUE);

if (app_info.Flavor != 'Normal')
  audit(AUDIT_INST_VER_NOT_VULN, app_info.display_name + ' ' + app_info.Flavor);

var constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '19.1.0.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);