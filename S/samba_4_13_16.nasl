#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156756);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/28");

  script_cve_id("CVE-2021-43566");
  script_xref(name:"IAVA", value:"2022-A-0020-S");

  script_name(english:"Samba 4.13.x < 4.13.16 Arbitrary Directory Write");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is potentially affected by an arbitrary directory write vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is 4.13.x prior to 4.13.16.  It is, therefore, potentially affected by
a SMB1 or NFS symlink race condition. A remote authenticated attacker, using the race condition, could potentially create
a directory outside of the exported share.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2021-43566.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/security.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.13.16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43566");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_set_attribute(attribute:"stig_severity", value:"III");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::samba::get_app_info();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [{'min_version':'4.13.0',  'fixed_version':'4.13.16'}];

vcf::check_version_and_report(app_info: app_info, constraints: constraints, severity: SECURITY_NOTE);
