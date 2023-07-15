#TRUSTED 306d2f0377849677385d92e3f67f3ace319d9ad13c81405e5a57ba4c0e8ee46019ba3edf862b9a5a798f92f68d1dabcdf41193c6ea651e67f9946561ca798a301dffc12b4409f7f2ea62183449e2ec1925a83ac2fe8ea6d38513d2b4243722748de389d9fb3f65666bce1cee85059da0f6cfefa961af7b69acc66a32e8cc4e6a48dd09615f0cf8e36d114a87283283907fb1acaa8cebb275297fc89e5001757cf04d8cd64b63a211e43a9dcb4ad78ccbae739dd9ecdcf00623310c05ed0024fc1d2cc76e9734c1a3a096d0fd210d004c17876b5a6babca6aff9603491cddc27c1f102c83fd59fab14dd252cb8be003cf5b458e97a22f58e443908a9ad4250c9cac5165e9143e2ab2b7ec9e59d3b4bba99f84266e70fcd3d30ba9240baad7df6a30d5e2b1db919197af467f1db785eec5df319ae40964d61523de081c458d491f3d96b7a9751f7b12517275e333dfa1483e0ff88f9e4486de9910064ab87ae1610c398e23bf219c164a7e6235c1baca5441f591f3ed081affe878799971d5c65c567ba980a3e4c148b5516cd5fdd4e838f9045284e4f40b3a07b7b426b0cd5f88c0713d06e4b29d8e8fe475b50a094aeae214ad277dd8bb88a46cd6ee4e7252b995596e4a54ad0bf7f2bdcf532b524f21e158fbef990d217d1e3a1219a572945a9df496cf35293de1e455885d7d12ed21958a7298a74175ac3b4267b9b94212d6
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129980);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/25");

  script_cve_id("CVE-2019-1779");
  script_bugtraq_id(108394);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj00418");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-fxos-cmdinj-1779");
  script_xref(name:"IAVA", value:"2019-A-0173");

  script_name(english:"Cisco FXOS Software Command Injection Vulnerability (CVE-2019-1779)");
  script_summary(english:"Checks the version of Cisco FXOS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FXOS Software is affected by the vulnerability that allows an 
authenticated, local attacker to execute arbitrary commands on the underlying operating system of an affected device
with elevated privileges. The vulnerability is due to insufficient validation of arguments passed to certain CLI
commands. An attacker could exploit this vulnerability by including malicious input as the argument of an affected
command. A successful exploit could allow the attacker to execute arbitrary commands on the underlying operating
system with elevated privileges. An attacker would need valid device credentials to exploit this vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-fxos-cmdinj-1779
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29bf8784");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj00418");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvj00418");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1779");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'FXOS');

if(
  isnull(product_info['model']) ||
  product_info['model'] !~ "^(41|93)[0-9]{2}$"
)
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '2.4.1.101'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvj00418'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
