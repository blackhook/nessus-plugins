#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173912);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/11");

  script_cve_id("CVE-2023-0614", "CVE-2023-0922");
  script_xref(name:"IAVA", value:"2023-A-0167");

  script_name(english:"Samba 4.x < 4.16.10 / 4.17.x < 4.17.7 / 4.18.x < 4.18.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is potentially affected by multiple vulnerabilities, as follows:

  - The fix in 4.6.16, 4.7.9, 4.8.4 and 4.9.7 for CVE-2018-10919 Confidential attribute disclosure via LDAP
    filters was insufficient and an attacker may be able to obtain confidential BitLocker recovery keys from a
    Samba AD DC. (CVE-2023-0614)

  - The Samba AD DC administration tool, when operating against a remote LDAP server, will by default send new
    or reset passwords over a signed-only connection. (CVE-2023-0922)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2023-0614.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2023-0922.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/security.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.16.10, 4.17.7, or 4.18.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0614");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::samba::get_app_info();

if (report_paranoia < 2) audit(AUDIT_POTENTIAL_VULN);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  {'min_version':'4.0',  'fixed_version':'4.16.10'},
  {'min_version':'4.17',  'fixed_version':'4.17.7'},
  {'min_version':'4.18',  'fixed_version':'4.18.1'}
];

vcf::check_version_and_report(app_info: app_info, constraints: constraints, severity: SECURITY_WARNING);
