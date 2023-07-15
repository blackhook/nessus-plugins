#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('compat.inc');

if (description)
{
  script_id(166329);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/01");

  script_cve_id("CVE-2022-41032");
  script_xref(name:"IAVA", value:"2022-A-0413-S");

  script_name(english:"Security Update for Visual Studio 2022 (Oct 2022) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products installed on the remote macOS or Mac OS X host is missing a security update.
It is, therefore, affected by an escalation of privilege vulnerability. A local attacker can gain the privileges of
the user running the Microsoft Visual Studio Application.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported
version");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/mac-release-notes#1737--visual-studio-2022-for-mac-v1737-newreleasebutton
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6aebfb11");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released Visual Studio 2022 version 17.3.8 build 5 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41032");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("visual_studio_mac_installed.nbin");
  script_require_keys("installed_sw/Visual Studio", "Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version')) audit(AUDIT_OS_NOT, 'macOS / Mac OS X');

var app_info = vcf::get_app_info(app:'Visual Studio');
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [ {'min_version': '17.3', 'fixed_version': '17.3.8'} ];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
