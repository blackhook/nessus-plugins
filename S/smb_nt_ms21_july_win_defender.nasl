#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151647);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/26");

  script_cve_id("CVE-2021-34464", "CVE-2021-34522");

  script_name(english:"Security Update for Windows Defender (July 2021)");

  script_set_attribute(attribute:"synopsis", value:
"An antimalware application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Malware Protection Engine version of Microsoft Windows Defender installed on the remote Windows host
is prior to 1.1.18242.0. It is, therefore, affected by multiple remote code execution vulnerabilities. An
attacker can exploit one of these vulnerabilities to bypass authentication and execute unauthorized arbitrary
commands.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34464
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ff8e1a1");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34522
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d20e15da");
  script_set_attribute(attribute:"solution", value:
"Enable automatic updates to update the malware engine for the relevant antimalware applications.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34522");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_defender");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_windows_defender_win_installed.nbin");
  script_require_keys("installed_sw/Windows Defender");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app = 'Windows Defender';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

# Check if disabled
if (!isnull(app_info['Disabled']))
  exit(0,'Windows Defender is disabled.');

# Check if we got the Malware Engine Version
if (isnull(app_info['Engine Version']))
  exit(0,'Unable to get the Malware Engine Version.');

var constraints = [{'fixed_version':'1.1.18242.0'}];

vcf::av_checks::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, check:'Engine Version');
