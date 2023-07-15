#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175434);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/17");

  script_cve_id("CVE-2023-28759");
  script_xref(name:"IAVA", value:"2023-A-0181");

  script_name(english:"Veritas NetBackup prior to 10.0 Privilege Escalation (VTS23-006)");

  script_set_attribute(attribute:"synopsis", value:
"A back-up management application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Veritas NetBackup application installed on the remote Windows 
host is prior to 10.0 or is missing a vendor-supplied security hotfix. It is, therefore, affected by privilege
escalation vulnerability. An issue was discovered in Veritas NetBackup before 10.0. A vulnerability in the way NetBackup
validates the path to a DLL prior to loading may allow a lower level user to elevate privileges and compromise the
system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/content/support/en_US/security/VTS23-006");
# https://www.veritas.com/content/support/en_US/downloads/update.UPD685700
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77f64edb");
# https://www.veritas.com/content/support/en_US/downloads/update.UPD972396
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dcbf9da1");
# https://www.veritas.com/content/support/en_US/downloads/update.UPD455459
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e9e0740");
# https://www.veritas.com/content/support/en_US/downloads/update.UPD875613
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d1058ca");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Veritas NetBackup version 10.0 or later or apply the appropriate EEB or hotfix.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28759");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veritas:netbackup");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("veritas_netbackup_installed.nbin");
  script_require_keys("installed_sw/NetBackup");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'NetBackup', win_local:TRUE);

var hotfixes = app_info.Patches;

var install_type = tolower(app_info['Install type']);
if ('client' >!< install_type && 'server' >!< install_type)
  audit(AUDIT_HOST_NOT, 'affected');

var constraints;
var fixed_version = '10.0';
if (!empty_or_null(pregmatch(pattern: "8\.3\.0\.1", string:app_info.version)))
{
  if ('4115799' >< hotfixes) fixed_version = '8.3.0.1';
  constraints = [{ 'fixed_version' : fixed_version, 'fixed_display' : 'Install hotfix ET4115799 per vendor advisory or upgrade to 10.0' }];
}
else if (!empty_or_null(pregmatch(pattern: "8\.3\.0\.2", string:app_info.version)))
{
  if ('4116057' >< hotfixes) fixed_version = '8.3.0.2';
  constraints = [{ 'fixed_version' : fixed_version, 'fixed_display' : 'Install hotfix ET4116057 per vendor advisory or upgrade to 10.0'  }];
}
else if (!empty_or_null(pregmatch(pattern: "9\.0\.0\.1", string:app_info.version)))
{
  if ('4116060' >< hotfixes) fixed_version = '9.0.0.1';
  constraints = [{ 'fixed_version' : fixed_version, 'fixed_display' : 'Install hotfix ET4116060 per vendor advisory or upgrade to 10.0'  }];
}
else if (!empty_or_null(pregmatch(pattern: "9\.1\.0\.1", string:app_info.version)))
{
  if ('4115260' >< hotfixes) fixed_version = '9.1.0.1';
  constraints = [{ 'fixed_version' : fixed_version, 'fixed_display' : 'Install hotfix ET4115260 per vendor advisory or upgrade to 10.0'  }];
}
else
{
  constraints = [{ 'fixed_version' : '10.0' }];
}

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);