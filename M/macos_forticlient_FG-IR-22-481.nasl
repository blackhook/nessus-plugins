#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174259);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_cve_id("CVE-2023-22635");

  script_name(english:"Fortinet FortiClient (Mac) - update functionality may lead to privilege escalation vulnerability (FG-IR-22-481) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"remote Mac host is affected by a privilege escalation.");
  script_set_attribute(attribute:"description", value:
"The version of FortiClient installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-22-481 advisory.

  - A download of code without Integrity check vulnerability [CWE-494] in FortiClientMac version 7.0.0 through
    7.0.7, 6.4 all versions, 6.2 all versions, 6.0 all versions, 5.6 all versions, 5.4 all versions, 5.2 all
    versions, 5.0 all versions and 4.0 all versions may allow a local attacker to escalate their privileges
    via modifying the installer upon upgrade. (CVE-2023-22635)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-22-481");
  script_set_attribute(attribute:"solution", value:
"Please upgrade to  FortiClientMac version 7.0.8 or above.
Please upgrade to  FortiClientMac version 7.2.0 or above.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22635");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macos_forticlient_detect.nbin");
  script_require_keys("installed_sw/FortiClient");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

var app_name = 'FortiClient';
var app_info = vcf::get_app_info(app:app_name);

var constraints = [
  { 'min_version' : '4.0.0', 'max_version' : '4.0.3', 'fixed_display' : '7.0.8' },
  { 'min_version' : '5.0.0', 'max_version' : '5.0.10', 'fixed_display' : '7.0.8' },
  { 'min_version' : '5.2.0', 'max_version' : '5.2.6', 'fixed_display' : '7.0.8' },
  { 'min_version' : '5.4.0', 'max_version' : '5.4.4', 'fixed_display' : '7.0.8' },
  { 'min_version' : '5.6.0', 'max_version' : '5.6.6', 'fixed_display' : '7.0.8' },
  { 'min_version' : '6.0.1', 'max_version' : '6.0.10', 'fixed_display' : '7.0.8' },
  { 'min_version' : '6.2.0', 'max_version' : '6.2.9', 'fixed_display' : '7.0.8' },
  { 'min_version' : '6.4.0', 'max_version' : '6.4.10', 'fixed_display' : '7.0.8' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.8' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
