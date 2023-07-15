#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135719);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/19");

  script_cve_id("CVE-2020-0835");

  script_name(english:"Security Updates for Windows Defender (April 2020)");
  script_summary(english:"Checks the MsMpEng.exe version.");

  script_set_attribute(attribute:"synopsis", value:
"An antimalware application installed on the remote host is affected by
a hard link elevation of privilege vulnerability.");
  script_set_attribute(attribute:"description", value:
"The engine version of Microsoft Windows Defender installed on the remote Windows host
is prior to 4.18.2001.112. It is, therefore, affected by a hard link elevation of privilege 
vulnerability which could allow an attacker who successfully exploited this vulnerability 
to elevate privileges on the system.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0835
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5520b9d8");
  script_set_attribute(attribute:"solution", value:
"Enable automatic updates to update the scan engine for the relevant antimalware applications. Refer to Knowledge Base
Article 2510781 for information on how to verify that MMPE has been updated.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0835");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_defender");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_windows_defender_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "SMB/svcs");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

app = 'Windows Defender';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

# Check if disabled
if (!isnull(app_info['Disabled']))
  exit(0,'Windows Defender is disabled.');

constraints = [{'max_version': '4.18.2001.111', 'fixed_version':'4.18.2001.112'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
