#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157360);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/03");

  script_cve_id("CVE-2021-44141", "CVE-2021-44142", "CVE-2022-0336");
  script_xref(name:"IAVA", value:"2022-A-0054-S");

  script_name(english:"Samba 4.0.x < 4.13.17 / 4.14.x < 4.14.12 / 4.15.x < 4.15.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is 4.0.x prior to 4.13.17, 4.14.x prior to 4.14.12, or 4.15.x prior
to 4.15.5.  It is, therefore, affected by multiple vulnerabilities:

  - Out-of-bounds heap read/write vulnerability in VFS module vfs_fruit allows code execution. (CVE-2021-44142)

  - Information leak via symlinks of existence of	files or directories outside of the exported share. (CVE-2021-44141)

  - Samba AD users with permission to write to an account can impersonate arbitrary services. (CVE-2022-0336)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/security.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2021-44141.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2021-44142.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2022-0336.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.13.17, 4.14.12, or 4.15.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44142");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0336");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'min_version':'4.0.0',  'fixed_version':'4.13.17'},
  {'min_version':'4.14.0',  'fixed_version':'4.14.12'},
  {'min_version':'4.15.0',  'fixed_version':'4.15.5'}
];

vcf::check_version_and_report(app_info: app_info, constraints: constraints, severity: SECURITY_HOLE);
