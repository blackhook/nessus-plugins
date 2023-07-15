#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150359);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/12");

  script_cve_id("CVE-2021-31978", "CVE-2021-31985");
  script_xref(name:"IAVA", value:"2021-A-0273-S");

  script_name(english:"Security Update for Windows Defender (June 2021)");

  script_set_attribute(attribute:"synopsis", value:
"An antimalware application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Malware Protection Engine version of Microsoft Windows Defender installed on the remote Windows host
is equal or prior to 1.1.17800.5. It is, therefore, affected by multiple vulnerabilities. 

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-31985)
    
  - A denial of service (DoS) vulnerability. An attacker can exploit this issue to cause the affected 
    component to deny system or application services. (CVE-2021-31978)");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31985
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db0f474f");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31978
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?51ebd435");
  script_set_attribute(attribute:"solution", value:
"Enable automatic updates to update the malware engine for the relevant antimalware applications. Refer to Knowledge Base
Article 2510781 for information on how to verify that MMPE has been updated.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31985");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_defender");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

app = 'Windows Defender';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

# Check if disabled
if (!isnull(app_info['Disabled']))
  exit(0,'Windows Defender is disabled.');

# Check if we got the Malware Engine Version
if (isnull(app_info['Engine Version']))
  exit(0,'Unable to get the Malware Engine Version.');

constraints = [{'fixed_version':'1.1.18200.3'}];

vcf::av_checks::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, check:'Engine Version');
