#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136177);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2020-10700", "CVE-2020-10704");
  script_xref(name:"IAVA", value:"2020-A-0175-S");

  script_name(english:"Samba 4.10.x < 4.10.15 / 4.11.x < 4.11.8 / 4.12.x < 4.12.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Samba.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is 4.10.x prior to
4.10.15, 4.11.x prior to 4.11.8, or 4.12.x prior to 4.12.2.  It is,
therefore, affected by the following vulnerabilities :

  - A flaw exists related to handling 'ASQ' and 'Paged
    Results' LDAP controls that could allow use-after-free
    conditions having unspecified impact. (CVE-2020-10700)

  - A flaw exists related to handling deeply nested
    filters, un-authenticated LDAP searches, and stack
    memory that could allow  application crashes.
    (CVE-2020-10704)

Note that Nessus has not tested for these  issues but has instead relied
only on the application's self-reported version number.");
  # https://www.samba.org/samba/security/CVE-2020-10700.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a8fcf070");
  # https://www.samba.org/samba/security/CVE-2020-10704.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0eb4abff");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.10.15 / 4.11.8 / 4.12.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10704");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'min_version':'4.10.0', 'fixed_version':'4.10.15'},
  {'min_version':'4.11.0', 'fixed_version':'4.11.8'},
  {'min_version':'4.12.0', 'fixed_version':'4.12.2'},
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE);
