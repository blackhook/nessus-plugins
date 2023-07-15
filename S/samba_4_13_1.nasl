##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142419);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-14318", "CVE-2020-14323", "CVE-2020-14383");
  script_xref(name:"IAVA", value:"2020-A-0508-S");

  script_name(english:"Samba 3.6.x < 4.11.15 / 4.12.x < 4.12.9 / 4.13.x < 4.13.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is 3.6.x prior to 4.11.15, 4.12.x prior to 4.12.9, or 4.13.x prior to
4.13.1.  It is, therefore, potentially affected by multiple vulnerabilities, including the following:

  - A null pointer dereference flaw was found in samba's Winbind service in versions before 4.11.15, before
    4.12.9 and before 4.13.1. A local user could use this flaw to crash the Winbind service causing denial of
    service. (CVE-2020-14323)

  - A missing permissions check on a directory handle can leak file name information to unprivileged accounts.
    (CVE-2020-14318)

  - An error in Samba's dnsserver RPC pipe when no data is present in the DNS records additional section. An
    authenticated, non-admin user can exploit this to crash the DNS server by adding invalid records.
    (CVE-2020-14383)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2020-14383.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2020-14323.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2020-14318.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/security.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.11.15 / 4.12.9 / 4.13.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14318");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/04");

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

include('vcf.inc');
include('vcf_extras.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = vcf::samba::get_app_info();
vcf::check_granularity(app_info:app, sig_segments:3);

constraints = [
  {'min_version':'3.6.0',  'fixed_version':'4.11.15'},
  {'min_version':'4.12.0', 'fixed_version':'4.12.9'},
  {'min_version':'4.13.0', 'fixed_version':'4.13.1'}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE);
