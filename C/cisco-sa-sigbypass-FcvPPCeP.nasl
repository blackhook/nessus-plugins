#TRUSTED a585ed793c314e30489e7d5f4f2fa61e96386d1949838e56c66738c661a15b9fcb76b604575ffa82177b4447e2733c0b5a41d64c1e189ba5cbad0e807a9ef9592e9250edd0b513f2942ef39cb681333d2f2aab0cab4399099abe5cb7ccd3d028344205af4b19cada9f78de04676c50c75ecd3bb1d7efd369caec82b4a42b1eb4be8681c5eaafd399ee05597e9a5611230ff46ab261ce32b830579cf7bb5afb858d3ec41ec8cc0b32d1b10b52114393953b2beb84191636afe3c8cf4c6314dfd41ad815a30ac03782a94b712a771c8ffab0354b000db71208c3d2e93d160e7dbc6c63243d94abc4de562a355ed6d6e503244e3f7c1494c8ae0552f79abb8d2e427862d72c8dfe76bfb1f0848ffea510e5e20803102fdef97cb4f9d4112081dba663b8518cd49cef12c579dcb5fc8523966657e34de133687378a6dbf8a76b8f42cc02fe77ee3751944b15483d8df6c835bf805910353fb28cb23e5bd7e07b3c50645fd559b28e79fa0b529a860190feb797f2cd626a3849e03324ab775664eee9caef5baa07905839345e6bf8486e439979a41d4ff6ffa15848520cf8ed475a4d7be4a78c658a5fa920db5fd1965a9964b4864b027dbb6b1fb247823b3b79d8a4bed86b7162e32f6621453567da9fc5d1bb458e8accb77cfee7baf61b6e998bf88c4d7c856f60dbdd958d9bb8daf0ec8262b985043d1d6231e4627492dc93dfcd
#TRUST-RSA-SHA256 311a71b467379bc90571845b880b909b72ff3794347ace9b5756eb1eaf3e6981497b4fea9b6c6a28bb919805af71906c8cba01f98f395217f4b2b50daab343b175e9b7ae9cc4024ebe125d37fdf3fe6d38a5a567232ff288c8a0b50504d235db72140d1e46ce22e3d474f92f7be56f7b1b2102e1961156d263a37eb1a1ce81db1ce3512aa52552da6b6d3bc6fb2c9f3eab8e5aa2882ec20150d7c40d9de0920750a622789e8891edb273f9dfdd700b33d8e3f5769f1451b9fb89e9c8abdfd35e9b8e43858685261b3ce9c54e906c3b7216efa0710c82dd10fc201470e22167a94eec4b8a2f809f93f69e5f48e16a83165e9bb8baba641029c5c37fb812ca4d84a518093f3339169bcd35ea6f2bdfb56abf62583344036fc052001bf5b433fed6fe5da56a5e715b9f4505a8a59824d9a3c6079efd9cccdb382f1d8b26b87946c632b18e40611394749d8e3ef978237eec1b04769bacd928d65e67e9fd7f18cf4eb1d7b5cb3bf86e4e704e18c76b3d8ab5e57ce39aaec2611381219f38b1819ef9e99793ad1a701f4a5c95dcd70fde7fa6bde3ec324167069cd4245e73e4453294412472aede34dba3efe779ba520c1ae19f07b97c4d06b2ab9f9edc90b192022502309cda42e973f78283b26c2d46c945f3b1ce8cba65ff224a3c5e18fc175d176e6bd9f6435992d187c030552840e7e0a10c459565c1fcd382c6afb517cf3aa4
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136671);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3308");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg16015");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sigbypass-FcvPPCeP");
  script_xref(name:"IAVA", value:"2020-A-0205-S");

  script_name(english:"Cisco Firepower Threat Defense Software Signature Verification Bypass (cisco-sa-sigbypass-FcvPPCeP)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by a signature verification
bypass vulnerability due to improper verification of digital signatures for patch images. An authenticated, remote
attacker can exploit this, by crafting an unsigned software patch, to boot a malicious software patch image.

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sigbypass-FcvPPCeP
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f75db639");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg16015");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvg16015.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3308");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(347);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '6.2.2.1'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvg16015',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
