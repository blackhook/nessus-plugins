#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133210);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/25");

  script_cve_id("CVE-2019-14902", "CVE-2019-14907", "CVE-2019-19344");
  script_xref(name:"IAVA", value:"2020-A-0035-S");

  script_name(english:"Samba 4.x < 4.9.18 / 4.10.x < 4.10.12 / 4.11.x < 4.11.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is 4.x prior to 4.9.18, 4.10.x prior to 4.10.12, or 4.11.x prior to
4.11.5.  It is, therefore, affected by multiple vulnerabilities:

  - An issue exists with ACL inheritance due to added or removed delegated rights not being inherited across
    domain controllers. An authenticated, remote attacker can exploit this to create or remove a subtree when
    the permission should have been removed from the user. (CVE-2019-14902)

  - A denial of service (DoS) vulnerability exists due to Samba incorrectly converting characters printed
    during the NTLMSSP exchange when the log level is set to 3. An authenticated, remote attacker can exploit
    this issue, to cause some long-lived processes like the RPC server to stop responding. (CVE-2019-14907)

  - A use-after-free error exists in the code used to 'tombstone' dynamically created DNS records that have
    reached their expiry time, due to an improper realloc() call. An authenticated, remote attacker may be
    able to exploit this to cause read memory to be written to the DB. (CVE-2019-19344)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2019-14902.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2019-14907.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2019-19344.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.9.18 / 4.10.12 / 4.11.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14902");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = vcf::samba::get_app_info();
vcf::check_granularity(app_info:app, sig_segments:3);

constraints = [
  {'min_version':'4.0.0', 'fixed_version':'4.9.18'},
  {'min_version':'4.10.0', 'fixed_version':'4.10.12'},
  {'min_version':'4.11.0', 'fixed_version':'4.11.5'}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE);
