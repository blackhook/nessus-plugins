#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(146582);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/15");

  script_cve_id("CVE-2021-1733");

  script_name(english:"Sysinternals PsExec Elevation of Privilege (CVE-2021-1733)");

  script_set_attribute(attribute:"synopsis", value:
"Sysinternals PsExec Elevation of Privilege Vulnerability.");
  script_set_attribute(attribute:"description", value:
"An elevation of privilege vulnerability exists in Sysinternals PsExec due to the application not properly imposing
security restrictions in PsExec, which leads to a security restrictions bypass and privilege escalation. It is possible
for a local attacker who is authenticated as a non-admin user to use the PsExec binary to escalate to SYSTEM.

Note: There has been new PsExec versions released in 2021 (v2.30 and v2.32), but Tenable has confirmed them to also be
vulnerable to this Local Privilege Escalation with minor PoC adjustments. Nessus has not tested for this issue but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1733");
  # https://medium.com/tenable-techblog/psexec-local-privilege-escalation-2e8069adc9c8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?308b912b");
  script_set_attribute(attribute:"solution", value:
"Upgrade PsExec to version 2.33 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1733");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:psexec");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pstools_detect_win.nbin");
  script_require_keys("installed_sw/PsExec");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'PsExec', win_local:TRUE);

constraints = [
  { 'min_version' : '1.72', 'max_version' : '2.32', 'fixed_display':'Update to v2.33 or later.
  Note: There has been new PsExec versions released in 2021
  (v2.30 and v2.32), but Tenable has confirmed them to also be
  vulnerable to this Local Privilege Escalation with minor PoC adjustments.' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
