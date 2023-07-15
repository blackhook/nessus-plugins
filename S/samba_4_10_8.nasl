#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128549);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2019-10197");

  script_name(english:"Samba 4.9.x < 4.9.13 / 4.10.x < 4.10.8 / 4.11.0rc3 Security Bypass (CVE-2019-10197)");
  script_summary(english:"Checks the version of Samba.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is potentially affected by a man in the middle vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is 4.9.x prior to 
4.9.13, 4.10.x prior to 4.10.3.8, or 4.11.x prior to 4.11.0rc3. 
It is, therefore, affected by security bypass vulnerability.
An unauthenticated attacker could use this flaw to escape the shared 
directory and access the contents of directories outside the share.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://www.samba.org/samba/security/CVE-2019-10197.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0002d667");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.9.13 / 4.10.8 / 4.11.0rc3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10197");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('vcf.inc');
include('vcf_extras.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = vcf::samba::get_app_info();
vcf::check_granularity(app_info:app, sig_segments:3);

constraints = [
  {'min_version':'4.9.0rc0', 'fixed_version':'4.9.13'},
  {'min_version':'4.10.0rc0', 'fixed_version':'4.10.8'},
  {'min_version':'4.11.0rc0', 'fixed_version':'4.11.0rc3'}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE);
