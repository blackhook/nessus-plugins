#TRUSTED 961860857b35c5ad2f833310453c69c9808338a6be083832314566de23d55c09e58ca4d234b1b3c6caea4bc3ebdf1f6b4d4ad9e2354f9c9b50bc969d81ceb76257057a6dc9d57e8f19ed9da4148ea5c949c9cc2f16709087281c3bf4f39d1aa51f11e9d94e5800bf7699d7dcb00db54b49196cd19b62a624d9098f19c4944f395eed4c6636b3fddf21d6b58ec422dcbfa795f3285a6a1f1440fa325bc05a063a2ab3309098cc4fe6f46f193e0b91d53d46cad75cb86a5b342e871a94142657ae9046aafed586fb1b219e53abe408cd431c706146d9b2edc8a4ccbd6e6753a463ffbb3fc8e12280824e9331ccd82117a2e0a8559894cc0503f9f3eaba8f24370ded1d2cc502a571611cd03810dca2cf8d01aa35b16086751e7ab8544525e9181ecf70a79c9114f1e0844e6a597fc90c1cdf8ff7066d74936b1fb400c1c8fae5689adca779cb019caf200a4de9ab686c8ec4ec84c71c7746644590b6cc9847c57e9daf79321fbf54e694cc78e719881d60f35e9334698c822b00c6a4ca625902bea4ef78dbf2bc166e8929bd30ec60b914a84d90fb92ec9d229cad25b8769604ab1ef025aea38804f5b0c9281a0ec9b3ab76ef1e760bbe01d6457ab2e8155e8370799d9732a51182fe92994b2001856049eca7208de73ff37cf71964e59a707fb2f7d09f38d29399dca9f15f14eb31e7ab0e2183ef9ca63d29d0dcd2ca173bf4af
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128532);
  script_version("1.6");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-1901");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp92121");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190731-nxos-bo");
  script_xref(name:"IAVA", value:"2019-A-0317");

  script_name(english:"Cisco Nexus 9000 Series Fabric Switches ACI Mode Link Layer Discovery Protocol Buffer Overflow Vulnerability");
  script_summary(english:"Checks the version of Cisco NX-OS System Software in ACI Mode");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco NX-OS Software in
ACI mode is affected by a buffer overflow vulnerability. An
unauthenticated, adjacent attacker could exploit this vulnerability,
via a specially crafted Link Layer Discovery Protocol (LLDP) packet,
to cause a denial-of-service condition or potentially execute arbitrary
code with root privileges. Please see the reference Cisco BID and Cisco
Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190731-nxos-bo
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd3ed165");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp92121");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp92121");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1901");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");


  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info['device'] || product_info['model'] !~ '^90[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '14.1.2g',
  '14.1.1l',
  '14.1.1k',
  '14.1.1j',
  '14.1.1i',
  '14.0.3d',
  '14.0.2c',
  '14.0.1h',
  '13.2.6i',
  '13.2.5f',
  '13.2.5e',
  '13.2.5d',
  '13.2.4e',
  '13.2.4d',
  '13.2.3s',
  '13.2.3r',
  '13.2.3o',
  '13.2.3n',
  '13.2.3j',
  '13.2.3i',
  '13.2.2o',
  '13.2.2l',
  '13.2.1m',
  '13.2.1l',
  '13.1.2u',
  '13.1.2t',
  '13.1.2s',
  '13.1.2q',
  '13.1.2p',
  '13.1.2o',
  '13.1.2m',
  '13.1.1i',
  '13.0.2n',
  '13.0.2k',
  '13.0.2h',
  '13.0.1k',
  '12.3.1p',
  '12.3.1o',
  '12.3.1l',
  '12.3.1i',
  '12.3.1f',
  '12.3.1e',
  '12.2.4r',
  '12.2.4q',
  '12.2.4p',
  '12.2.4f',
  '12.2.3t',
  '12.2.3s',
  '12.2.3r',
  '12.2.3p',
  '12.2.3j',
  '12.2.2q',
  '12.2.2k',
  '12.2.2j',
  '12.2.2i',
  '12.2.2g',
  '12.2.2f',
  '12.2.2e',
  '12.2.1o',
  '12.2.1n',
  '12.1.4a',
  '12.1.3j',
  '12.1.3h',
  '12.1.3g',
  '12.1.2k',
  '12.1.2g',
  '12.1.2e',
  '12.1.1i',
  '12.1.1h',
  '12.0.2o',
  '12.0.2n',
  '12.0.2m',
  '12.0.2l',
  '12.0.2h',
  '12.0.2g',
  '12.0.2f',
  '12.0.1r',
  '12.0.1q',
  '12.0.1p',
  '12.0.1o',
  '12.0.1n',
  '12.0.1m',
  '11.3.2k',
  '11.3.2j',
  '11.3.2i',
  '11.3.2h',
  '11.3.2f',
  '11.3.1j',
  '11.3.1i',
  '11.3.1h',
  '11.3.1g',
  '11.2.3m',
  '11.2.3h',
  '11.2.3e',
  '11.2.3c',
  '11.2.2j',
  '11.2.2i',
  '11.2.2h',
  '11.2.2g',
  '11.2.1m',
  '11.2.1k',
  '11.2.1i',
  '11.1.4m',
  '11.1.4l',
  '11.1.4i',
  '11.1.4g',
  '11.1.4f',
  '11.1.4e',
  '11.1.4',
  '11.1.3f',
  '11.1.2i',
  '11.1.2h',
  '11.1.1s',
  '11.1.1r',
  '11.1.1o',
  '11.1.1j',
  '11.0.4q',
  '11.0.4o',
  '11.0.4h',
  '11.0.3o',
  '11.0.3n',
  '11.0.3k',
  '11.0.3i',
  '11.0.3f',
  '11.0.2m',
  '11.0.2j',
  '11.0.1e',
  '11.0.1d',
  '11.0.1c',
  '11.0.1b'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvp92121'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
