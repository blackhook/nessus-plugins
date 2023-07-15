#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132023);
  script_version("1.4");
  script_cvs_date("Date: 2020/01/23");

  script_cve_id("CVE-2019-14861", "CVE-2019-14870");

  script_name(english:"Samba 4.x < 4.9.17 / 4.10.x < 4.10.11 / 4.11.x < 4.11.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Samba.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is 4.x prior to 4.9.17, 4.10.x prior to 4.10.11, or 4.11.x prior to
4.11.3.  It is, therefore, affected by multiple vulnerabilities:

  - A denial of service (DoS) vulnerability exists in the ldb_qsort() and dns_name_compare() routines due to
    how the routines handle case sensitivity of DNS records. An authenticated, remote attacker can exploit
    this issue, by registering a DNS record matching the name of the DNS zone, to cause the process to stop
    responding. (CVE-2019-14861)

  - An issue exists where the S4U (MS-SFU) Kerberos delegation model includes a feature allowing for a subset
    of clients to be opted out of constrained delegation in any way, either S4U2Self or regular Kerberos
    authentication, by forcing all tickets for these clients to be non-forwardable. In AD this is implemented
    by a user attribute delegation_not_allowed (aka not-delegated), which translates to disallow-forwardable.
    However the Samba AD DC does not do that for S4U2Self and does set the forwardable flag even if the
    impersonated client has the not-delegated flag set. (CVE-2019-14870)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2019-14861.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2019-14870.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.9.17 / 4.10.11 / 4.11.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14870");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'min_version':'4.0.0', 'fixed_version':'4.9.17'},
  {'min_version':'4.10.0', 'fixed_version':'4.10.11'},
  {'min_version':'4.11.0', 'fixed_version':'4.11.3'}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE);
