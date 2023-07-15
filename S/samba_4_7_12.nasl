#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119306);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id(
    "CVE-2018-14629",
    "CVE-2018-16841",
    "CVE-2018-16851",
    "CVE-2018-16852",
    "CVE-2018-16853",
    "CVE-2018-16857"
  );

  script_name(english:"Samba 4.7.x < 4.7.12 / 4.8.x < 4.8.7 / 4.9.x < 4.9.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Samba.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is 4.7.x prior to
4.7.12, or 4.8.x prior to 4.8.7, or 4.9.x prior to 4.9.3. It is,
therefore, affected by multiple vulnerabilities.

Notes: 
  - Refer to vendor advisories for possible workarounds.
  - CVE-2018-16852 and CVE-2018-16857 only apply to 4.9.x.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2018-14629.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2018-16841.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2018-16851.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2018-16852.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2018-16853.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2018-16857.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/samba-4.7.12.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/samba-4.8.7.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/samba-4.9.3.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.7.12 / 4.8.7 / 4.9.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16857");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("vcf.inc");
include("vcf_extras.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = vcf::samba::get_app_info();
vcf::check_granularity(app_info:app, sig_segments:3);

# Note: versions < 4.7 are EOL
constraints = 
[
  {"min_version" : "4.7.0", "fixed_version" : "4.7.12"},
  {"min_version" : "4.8.0", "fixed_version" : "4.8.7"},
  {"min_version" : "4.9.0", "fixed_version" : "4.9.3"}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE);