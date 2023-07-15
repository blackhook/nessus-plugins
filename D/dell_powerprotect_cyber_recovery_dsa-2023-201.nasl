#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(177375);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id("CVE-2023-32465");
  script_xref(name:"IAVA", value:"2023-A-0307");

  script_name(english:"Dell PowerProtect Cyber Recovery Authentication Bypass (DSA-2023-201)");

  script_set_attribute(attribute:"synopsis", value:
"A data protection and recovery application installed on the remote host is affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Dell PowerProtect Cyber Recovery installed on the remote host is prior to 19.13.0.3. It is, therefore,
affected by an authentication bypass vulnerability. An authenticated, remote attacker can exploit this vulnerability
to get unauthorized admin access to the Cyber Recovery application, leading to a complete takeover of the affected
host.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-ie/000214943/dsa-2023-201-security-update-for-dell-powerprotect-cyber-recovery
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9f46d4b");
  script_set_attribute(attribute:"solution", value:
"Update to Dell PowerProtect Cyber Recovery version 19.13.0.3, or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32465");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:powerprotect_cyber_recovery");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_cyber_recovery_nix_installed.nbin");
  script_require_keys("installed_sw/Dell Cyber Recovery");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Dell Cyber Recovery');

var constraints = [
  { 'min_version' : '19.4', 'fixed_version' : '19.13.0.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
