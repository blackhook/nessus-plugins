#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166770);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id("CVE-2022-3437");
  script_xref(name:"IAVA", value:"2022-A-0447-S");

  script_name(english:"Samba 4.0.x < 4.15.11 / 4.16.x < 4.16.6 / 4.17.x < 4.17.2 Buffer Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is potentially affected by a heap buffer overflow");
  script_set_attribute(attribute:"description", value:
"A heap-based buffer overflow condition exists in all versions of Samba since 4.0 compiled with Heimdal Kerberos.
Heimdal's GSSAPI library routines unwrap_des() and unwrap_des3() (DES for Samba 4.11 and earlier, Triple-DES for later 
versions) contain a length-limited write heap buffer overflow on malloc() allocated memory when presented with a 
maliciously small packet. The issue can be avoided by compiling Samba with MIT Kerberos using the flag 
'--with-system-mitkrb5'. An authenticated, remote attacker can exploit this, via network, to cause a denial of service
condition or the execution of arbitrary code. (CVE-2022-3437)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2022-3437.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.15.11, 4.16.6, or 4.17.2 or later, or apply vendor workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3437");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/01");

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
  {'min_version':'4.0.0',  'fixed_version':'4.15.11'},
  {'min_version':'4.16.0',  'fixed_version':'4.16.6'},
  {'min_version':'4.17.0',  'fixed_version':'4.17.2'}
];

vcf::check_version_and_report(app_info: app_info, constraints: constraints, severity: SECURITY_WARNING);
