#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150859);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/21");

  script_cve_id(
    "CVE-2021-0070",
    "CVE-2021-0097",
    "CVE-2021-0101",
    "CVE-2021-0113"
  );
  script_xref(name:"IAVA", value:"2021-A-0287");

  script_name(english:"Intel Server Board M10JNP2SB Advisory (INTEL-SA-00474)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the Intel BIOS on the remote device is affected by multiple
vulnerabilities, as follows:

  - Buffer overflow in the BMC firmware for Intel(R) Server Board M10JNP2SB
  before version EFI BIOS 7215, BMC 8100.01.08 may allow an unauthenticated
  user to potentially enable an escalation of privilege via adjacent access.
  (CVE-2021-0101)

  - Improper input validation in the BMC firmware for Intel(R) Server Board
  M10JNP2SB before version EFI BIOS 7215, BMC 8100.01.08 may allow an
  unauthenticated user to potentially enable an escalation of privilege via
  adjacent access. (CVE-2021-0070)

  - Out of bounds write in the BMC firmware for Intel(R) Server Board M10JNP2SB
  before version EFI BIOS 7215, BMC 8100.01.08 may allow an unauthenticated
  user to potentially enable a denial of service via adjacent access.
  (CVE-2021-0113)

  - Path traversal in the BMC firmware for Intel(R) Server Board M10JNP2SB
  before version EFI BIOS 7215, BMC 8100.01.08 may allow an unauthenticated
  user to potentially enable a denial of service via adjacent access.
  (CVE-2021-0097)

Note that Nessus has not tested for this issue but has instead relied only on
the self-reported version number.");
  # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00474.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b333cccc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant BIOS and BMC firmware referenced in the vendor's advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0101");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:intel:bios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bios_get_info_ssh.nasl", "bios_get_info_smb_reg.nasl");
  script_require_keys("BIOS/Version", "BIOS/Vendor");

  exit(0);
}

include('vcf.inc');

var vendor, version, ver_parts, vcf_version, vcf_parsed_version, app_info, constraints;

vendor = get_kb_item_or_exit('BIOS/Vendor');
if (vendor !~ "^Intel($| )") exit(0, 'The BIOS vendor is not Intel.');

version = get_kb_item_or_exit('BIOS/Version');
version = toupper(version);

# This is for M10JNP2SB, all server boards seem to have the model followed by 86B followed by 2 digits, 2 digits, 4
# digits, then, maybe, a timestamp.
if (version !~ "^M10JNP2SB\.86B\.\d{2}\.\d{2}\.\d{4}(\.|$)")
  audit(AUDIT_INST_VER_NOT_VULN, "Intel BIOS", version);

ver_parts = split(version, sep: '.', keep: FALSE);

# https://www.intel.com/content/dam/support/us/en/documents/motherboards/server/s3000ah/sb/d72579003_s3000ah_tps_1_4.pdf
# BoardFamilyID.OEMID.MajorRev.MinorRev.BuildID.BuildDateTime 
# Where BoardFamilyID here is M10JNP2SB, server boards usually use 86B for the OEMID, the major and minor rev are 2
# decimal digits, and the build ID is 4 decimal digits
# Assumes this 7.210 fix corresponds to the minor and build. Past plugins have just checked what would be the build
# here.
vcf_version = ver_parts[3] + '.' + ver_parts[4];

vcf_parsed_version = vcf::parse_version(vcf_version);
app_info = make_array(
  'app', 'Intel BIOS',
  'version', vcf_version,
  'display_version', version,
  'parsed_version' , vcf_parsed_version
);

constraints = [
  {'fixed_version' : '7.215', 'fixed_display' : 'EFI BIOS 7215, BMC 8100.01.08 or later'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);


