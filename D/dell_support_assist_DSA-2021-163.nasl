#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153806);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/25");

  script_cve_id("CVE-2021-36286", "CVE-2021-36297");
  script_xref(name:"IAVA", value:"2021-A-0444-S");

  script_name(english:"Dell SupportAssist < 3.10 Multiple Vulnerabilities (DSA-2021-163)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a Dell SupportAssist that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Dell SupportAssist Client Consumer is prior to 3.10. It
is, therefore, affected by multiple vulnerabilities.

  - An arbitrary file deletion vulnerability exists due to how Dell SupportAssist handles symbolic links and
    NTFS junction points. Symbolic links can be created by any(non-privileged) user under some object
    directories, but by themselves are not sufficient to successfully escalate privileges. However, combining
    them with a different object, such as the NTFS junction point allows for the exploitation. Support assist
    clean files functionality do not distinguish junction points from the physical folder and proceeds to
    clean the target of the junction that allows nonprivileged users to create junction points and delete
    arbitrary files on the system which can be accessed only by the admin. (CVE-2021-36286)

  - An untrusted search path vulnerability exists that allows attackers to load an arbitrary .dll file via
    .dll planting/hijacking, only by a separate administrative action that is not a default part of the
    SOSInstallerTool.exe installation for executing arbitrary dll's. (CVE-2021-36297)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-us/000191057/dsa-2021-163-dell-supportassist-client-consumer-security-update-for-two-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f2c887e5");
  script_set_attribute(attribute:"solution", value:
"Update Dell SupportAssist to version 3.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36297");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:supportassist");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_supportassist_installed.nbin");
  script_require_keys("installed_sw/Dell SupportAssist");

  exit(0);
}
include('vcf.inc');

var app_info = vcf::get_app_info(app:'Dell SupportAssist', win_local:TRUE);
var dell_edition = tolower(app_info['Edition']);

if ('business' >< dell_edition)
  var constraints = [
    {'fixed_version':'3.0.0'}
  ]; 

else constraints = [{'fixed_version':'3.10'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
