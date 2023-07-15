#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168018);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/06");

  script_cve_id("CVE-2022-42898");
  script_xref(name:"IAVA", value:"2022-A-0495-S");

  script_name(english:"Samba < 4.15.12, 4.16.x < 4.16.7, and 4.17.x < 4.17.3 32-Bit Systems Buffer Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is potentially affected by a buffer overflow vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is prior to 4.15.12, 4.16.x prior to 4.16.7, or 4.17.x prior to 4.17.3.
It is, therefore, potentially affected by a buffer overflow condition in the bundled Kerberos libraries due to a miss
calculation of bytes to allocate for a buffer. An authenticated, remote attacker can exploit this, via a specially
crafted ticket containing Privilege Attribute Certificates, to cause a denial of service condition or read beyond the
memory bounds.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2022-42898.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.15.12, 4.16.7, 4.17.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42898");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/21");

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

vcf::check_granularity(app_info:app_info, sig_segments:3);

if (report_paranoia < 2) audit(AUDIT_POTENTIAL_VULN, 'Samba', app_info.version);

var constraints = [
  {'fixed_version':'4.15.12'},
  {'min_version':'4.16.0',  'fixed_version':'4.16.7'},
  {'min_version':'4.17.0',  'fixed_version':'4.17.3'}
];

vcf::check_version_and_report(app_info: app_info, constraints: constraints, severity: SECURITY_HOLE);
