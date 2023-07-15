#TRUSTED 4bc4f14334ce531721f535ad54e6cd8d91214ae4e9b497efd1d99ce28345c4f1106b75fc8e713c4c9cf08f9acdd92d4a0e2f7974eea44332f2a89dbd235e5af2d09c2b2216dcd9a63f3d6cc1187ba56e2a0660959d37374443df608b6f14602adc55dd0dcb29e59d3dd8e73f0fcd1b31113e443ac2880ab824e9d6a13e9ba6e7a158bc771bf745b068ec234cacfaa2f1dec1dbec581a7b0bd20ab2aca2f7c3f866f794fef5f17fb979979971880dda4abf79a1ea1da1c69eecaebdf3c3c4651008bf7302df04d4eb75ef62255761501a36345975219d51e28eaef44828cde07b8df48027b80744a690e287d6767a42fb9bd0185727c07c5d01b84f1e5fdc7f3405e63cbda20e5b5af462a41b27c3ea26c622fcc2778a5cba932e42f7c0b07036bb1d37e8a75003de2c92cc52c7ffbd79d78cf7b6ac5de5d0bb2d2a91aa6bffc0e65055a592e476bd6221cf15e3c7ed4450c6aaa8751d87013caa1774f712cc7f561531a774c3e1f7b6c4bf55079d281ba4afd89851e85ba68bdb51c63e6fa6026808e33e9c9e835dabc4761d8b56671d7986c2b27ad9a239e48efbffd01c68020e974c3b619c67e13e23cb711da6c0854195a92f086605d2bd58e97bdf49d85b335d022738a960caa21230e444cc52728ff06fb21024f52e36717ed97f6cf94f8ddf5f6e0345ad70a18dbfa6056c6d7050b6ee5e23439f1f457890745fdf330a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134234);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3172");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr37151");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200226-fxos-nxos-cdp");
  script_xref(name:"IAVA", value:"2020-A-0086");

  script_name(english:"Cisco FXOS Software Cisco Discovery Protocol Arbitrary Code Execution and DoS (cisco-sa-20200226-fxos-nxos-cdp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FXOS Software is affected by a vulnerability in the Cisco Discovery
Protocol feature due to insufficient validation of Cisco Discovery Protocol packet headers. An unauthenticated, adjacent
attacker can exploit this, by sending a crafted Cisco Discovery Protocol packet to a Layer-2 adjacent affected device,
in order to execute arbitrary code as root or cause a denial of service DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be9c7431/");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr37151");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr37151.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3172");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'FXOS');
product_info['model'] = product_info['Model'];

if(
  isnull(product_info['model']) ||
  product_info['model'] !~ "^(41|93)[0-9]{2}"
)
  audit(AUDIT_HOST_NOT, 'affected');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '2.6.1.187'},
  {'min_ver' : '2.7',  'fix_ver': '2.7.1.106'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr37151',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
