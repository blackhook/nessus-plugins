#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169505);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id(
    "CVE-2022-37966",
    "CVE-2022-37967",
    "CVE-2022-38023",
    "CVE-2022-45141"
  );
  script_xref(name:"IAVA", value:"2023-A-0004-S");

  script_name(english:"Samba < 4.15.13 / 4.16.x < 4.16.8 / 4.17.x < 4.17.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is prior to 4.15.13, 4.16.x prior to 4.16.8, or 4.17.x prior
to 4.17.4.  It is, therefore, affected by multiple vulnerabilities:

  - Windows Kerberos RC4-HMAC Elevation of Privilege Vulnerability. (CVE-2022-37966, CVE-2022-45141)

  - Windows Kerberos Elevation of Privilege Vulnerability. (CVE-2022-37967)

  - Netlogon RPC Elevation of Privilege Vulnerability. (CVE-2022-38023)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/security.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2022-38023.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2022-37966.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2022-37967.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2022-45141.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.15.13, 4.16.8, or 4.17.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-45141");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/04");

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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  {'min_version':'0.0.0',  'fixed_version':'4.15.13'},
  {'min_version':'4.16.0',  'fixed_version':'4.16.8'},
  {'min_version':'4.17.0',  'fixed_version':'4.17.4'}
];

vcf::check_version_and_report(app_info: app_info, constraints: constraints, severity: SECURITY_HOLE);
