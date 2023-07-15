#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159916);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id("CVE-2022-24548");
  script_xref(name:"MSKB", value:"4052623");
  script_xref(name:"MSFT", value:"MS22-4052623");

  script_name(english:"Security Updates for Windows Defender (April 2022)");

  script_set_attribute(attribute:"synopsis", value:
"An antimalware application installed on the remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Malware Protection Engine version of Microsoft Windows Defender installed on the remote Windows host is equal or
prior to 1.1.19100.5. It is, therefore, affected by a denial of service vulnerability. An attacker can exploit this
to bypass authentication and execute unauthorized arbitrary commands.");
  # https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/manage-updates-baselines-microsoft-defender-antivirus?view=o365-worldwide
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3bed4ba6");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB4052623 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24548");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_defender");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var constraints = [
{'fixed_version':'1.1.19100.5'}
];

vcf::av_checks::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, check:'Engine Version');
