#TRUSTED 0a693dc1126fe3e419145797a860f1d569d966f2b97fe6adba0e8e1d17d5d22069f45dbda22179f1712e10a43e4b798996f63c66c8e1e4886755b6fe6b75a8a228ea885e44f3eef92970c45499cc8334df54e49c3efd40b37af4f101a0550930a69d2fac925b6b83fe0cb2b837fd061c14a78286fd28b2b45cbd9a9b60a956892ee49cd3ba2318e6dd7e77409a2c3f27dffece2646cdc1b98124be4f33ddd2be4242b234e44d12832827d6ef8e1ebcd2f19299d43034b7855c4bb4736ec1b972c893853da7f12f77c5f6bfdf057f94dd6ded0bee5af70f0b59e6afa04ae1bb527149bcca82f7e665f981c49a19af1b17fbed0bd324924ae7e1864f798bcaa34043b6a835aa1c323419fc350939a2375cd2320402b726b1bdc92e17d48a12fefcee04a1382d76c7518b5fbd1ee0aee2d6387a54027e47724ac349b491bc4c084ddd94c3aee60149ee77e5dfe8221a84704ddc3b778f350032d8d59ed9e0ed5990649514676e4251c89cb667fb8d52b719bec71f8182c38297a96fd60a288e33b3f79a0ff595a04535eb0a945890275b7a91c0ecad74c010513588e4f6b6c645fa37e97df585a9c59d4776fdec8951ce4e036184fe18ab9bbd355788a876a423ffb34ecc50ae73efe44082fd3aef9b3310e4b1e43d5a74e8487dfc3559d21e4d720a697d312221c5d6f4c4cdb02fa933f0da305e6fd33e736be5865f0648599f6b
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139036);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3262");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq59667");
  script_xref(name:"CISCO-SA", value:"cisco-sa-wlc-capwap-dos-Y2sD9uEw");
  script_xref(name:"IAVA", value:"2019-A-0424");

  script_name(english:"Cisco Wireless LAN Controller CAPWAP DoS (cisco-sa-wlc-capwap-dos-Y2sD9uEw)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Control and Provisioning of Wireless Access Points (CAPWAP) protocol
handler of Cisco Wireless LAN Controller (WLC) is affected by a vulnerability due to insufficient validation of CAPWAP
packets. An unauthenticated, remote attacker can exploit this, by sending a malformed CAPWAP packet to an affected
device, in order to cause a denial of service (DoS).

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-capwap-dos-Y2sD9uEw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15aca64f");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73978");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq59667");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq59667");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3262");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_(wlc)");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

vuln_ranges = [
                { 'min_ver' : '0.0', 'fix_ver' : '8.5.160.0'},
                { 'min_ver' : '8.6', 'fix_ver' : '8.8.130.0'},
                { 'min_ver' : '8.9', 'fix_ver' : '8.10.105.0'}
              ];

reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvq59667',
'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
