#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166908);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id("CVE-2022-3592");
  script_xref(name:"IAVA", value:"2022-A-0447-S");

  script_name(english:"Samba 4.17.x < 4.17.2 Symlink Following");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is potentially affected by a UNIX symbolic link (symlink) following vulnerability");
  script_set_attribute(attribute:"description", value:
"A UNIX symbolic link (symlink) following vulnerability exists in all versions of Samba since 4.17, which introduced
following symlinks in user space shares configured by an administrator. Improper symlink target checking in a corner
case leads to a user being able to create a symbolic link that will make the Samba daemon (smbd) escape the configured
share path.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2022-3592.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.17.2 or later, or apply vendor workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3592");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::samba::get_app_info();

vcf::check_granularity(app_info:app_info, sig_segments:1);

if (report_paranoia < 2) audit(AUDIT_POTENTIAL_VULN, 'Samba', app_info.version);

var constraints = [
  {'min_version':'4.17.0',  'fixed_version':'4.17.2'}
];

vcf::check_version_and_report(app_info: app_info, constraints: constraints, severity: SECURITY_WARNING);
