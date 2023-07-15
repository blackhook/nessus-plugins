#TRUSTED 2f961060449bcf73cf336dbc1010f3705b189db4e4fe30eb48826dedbf291f0b37e24fc409fc73675a175eb47554717247844f92628e17cf1a8cddd7cc0acce5e0ad2739e301935dd6f945b3b65a582b18ceb9f616350c000762539fa2b7c47950e6111532dfcbb39e858fbc81633288dd1360d7c61dc77268da26223d43eb524a4a459f6024eacf8732c495c1fcba48de24e587e35ae0c87c2f99c298934bba282d47392250a751e09d2a877325bd99621c0cc91439e277eda0120f18d3a4700727bf616e4418c255ca5cc62ce97acee2e215866f3f7ec6a410ff9e6450a5bf91a7885e325c7492598b4682e2e294e95f74ee7755365ff76cfb756a80a18c6a454ef70df1ceaa6d74fe29ecd081f61ecdf6d0b8f2099ae1b8fb7a8797a9aa0a2ef5af18af48c55f4bfd5a93f24739b90d17bf5d6468a75c67bfc393598445617d0da0fe1d1f6a25e049539b03ff0a33a6d563a342a5e49789d8386c807b0fbbb261c07d63a5e8ca8a03ce15c769c0d52ad2a84175ef0d5c99b1e64439407b632db540e37853ec05347ca837bf9ef80c53cc683253a15826cca404c73d7e07d4867d6437176524ed8835906ea64f2463ccf05577a703206c06a0f66ba18dfb279f72568b1010bfda86546b86acdd510c5c20143d546a303b7e2b1a594974c2d4ccb3cf58c845e2a1897b8a0f8924e382821cdb8bea5a22da42008e2b2dc3e037
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138349);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/20");

  script_cve_id("CVE-2018-0331");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc89242");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve40943");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve40953");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve40965");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve40970");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve40978");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve40992");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41000");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve41007");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-nxos-cdp");

  script_name(english:"Cisco FXOS, NX-OS, and UCS Manager Software Cisco Discovery Protocol DoS (cisco-sa-20180620-nxos-cdp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a denial of 
service (DoS) vulnerability exists in Cisco Discovery Protocol due to failure to properly 
validate certain fields within a Cisco Discovery Protocol message. An unauthenticated, 
adjacent attacker can exploit this issue, via submiting a Cisco Discovery Protocol message,
to cause the system to stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-nxos-cdp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31020d41");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc89242");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve40943");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve40953");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve40965");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve40970");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve40978");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve40992");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41000");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve41007");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvc89242, CSCve40943, CSCve40953, CSCve40965,
CSCve40970, CSCve40978, CSCve40992, CSCve41000, CSCve41007");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0331");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}
include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'FXOS');

if(product_info['model'] !~ "^(41|93)[0-9]{2}")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '2.0.1.152'},
  {'min_ver' : '2.1.1',  'fix_ver': '2.1.1.86'},
  {'min_ver' : '2.2',  'fix_ver': '2.2.1.70'},
  {'min_ver' : '2.2.2',  'fix_ver': '2.2.2.14'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['global_cdp_info'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCve41007'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  workarounds:workarounds,
  workaround_params:workaround_params
);