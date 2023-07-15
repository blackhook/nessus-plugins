#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(146334);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/05");

  script_cve_id("CVE-2021-24092");

  script_name(english:"Security Update for Windows Defender (February 2021)");

  script_set_attribute(attribute:"synopsis", value:
"An antimalware application installed on the remote host is affected by privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Malware Protection Engine version of Microsoft Windows Defender installed on the remote Windows host
is equal or prior to 1.1.17700.4. It is, therefore, affected by a unspecified privilege escalation vulnerability. An
authenticated, local attacker can exploit this to gain administrator access to the system.");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-24092
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba846d3c");
  script_set_attribute(attribute:"solution", value:
"Enable automatic updates to update the malware engine for the relevant antimalware applications. Refer to Knowledge Base
Article 2510781 for information on how to verify that MMPE has been updated.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-24092");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/09");

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

app = 'Windows Defender';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

# Check if disabled
if (!isnull(app_info['Disabled']))
  exit(0,'Windows Defender is disabled.');

# Check if we got the Malware Engine Version
if (isnull(app_info['Engine Version']))
  exit(0,'Unable to get the Malware Engine Version.');

constraints = [{'max_version': '1.1.17700.4', 'fixed_version':'1.1.17800.5'}];

vcf::av_checks::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, check:'Engine Version');
