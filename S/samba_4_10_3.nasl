#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125388);
  script_version("1.4");
  script_cvs_date("Date: 2019/10/30 13:24:46");

  script_cve_id("CVE-2018-16860");
  script_bugtraq_id(108332);

  script_name(english:"Samba 4.x < 4.8.12 / 4.9.x < 4.9.8 / 4.10.x < 4.10.3 Man in the Middle Vulnerability (CVE-2018-16860)");
  script_summary(english:"Checks the version of Samba.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is potentially affected by a man in the middle vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is 4.x prior to
4.8.12, 4.9.x prior to 4.9.8 or 4.10.x prior to 4.10.3. It is,
therefore, affected by a man in the middle vulnerability in the
Heimdal KDC due to an design error. An authenticated, remote
attacker can exploit this, via replacing the user name on
intercepted requests to the KDC, to bypass security restrictions.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://www.samba.org/samba/security/CVE-2018-16860.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b2593d1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.8.12 / 4.9.8 / 4.10.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16860");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:heimdal_project:heimdal");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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
  {'min_version':'4.0.0rc0', 'fixed_version':'4.8.0rc0', 'fixed_display':'4.8.12 / 4.9.8 / 4.10.3'},
  {'min_version':'4.8.0rc0', 'fixed_version':'4.8.12'},
  {'min_version':'4.9.0rc0', 'fixed_version':'4.9.8'},
  {'min_version':'4.10.0rc0', 'fixed_version':'4.10.3'}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE);
