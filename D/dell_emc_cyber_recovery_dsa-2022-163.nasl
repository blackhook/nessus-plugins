#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(175819);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/23");

  script_cve_id("CVE-2022-32481");
  script_xref(name:"IAVA", value:"2022-A-0267-S");

  script_name(english:"Dell Cyber Recovery Security Update Privilege Escalation Vulnerability (DSA-2022-163)");

  script_set_attribute(attribute:"synopsis", value:
"A data protection and recovery application installed on the remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Dell PowerProtect Cyber Recovery installed on the remote host is 19.x prior to 19.11. It is, therefore,
affected by a privilege escalation vulnerability on virtual appliance deployments. A lower-privileged authenticated user
can chain docker commands to escalate privileges to root leading to complete system takeover.

Note that Nessus has not tested for these issues but has instead relied only on the
application's self-reported version number.");
  # https://www.dell.com/support/kbdoc/en-ie/000201213/dsa-2022-163-dell-emc-cyber-recovery-security-update-for-multiple-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae6af7f8");
  script_set_attribute(attribute:"solution", value:
"Update to Dell PowerProtect Cyber Recovery version 19.11, or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32481");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:powerprotect_cyber_recovery");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_cyber_recovery_nix_installed.nbin");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Dell Cyber Recovery');

var virt_app = app_info["Virtual Appliance"];
if (!empty_or_null(virt_app))
{
  # only vuln if deployed as virtual appliance
  if (virt_app !~ 'True')
    audit(AUDIT_OS_CONF_NOT_VULN, app_info['app']);
}
else
{
  # check paranoia if no virt app entry
  if (report_paranoia < 2)
    audit(AUDIT_POTENTIAL_VULN);
}

var constraints = [
  { 'min_version' : '19.0', 'fixed_version' : '19.11' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);