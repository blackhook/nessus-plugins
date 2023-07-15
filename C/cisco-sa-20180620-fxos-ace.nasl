#TRUSTED 157383820aa2025309b7e6dfa6ad381a996002e9393343251d38e3a3f518c0a71644ea429122c16845b325546218b0464ce92927cd8741ef5abfb79427c175210ed8d850349aec06017ac1f17ba8cecad11f62449f64d2f40a9b0062ed4469da2d7e299a8c414c932504fd70d889b3e0cb0248df12d147d40a377b3dcdbeec79b925f17ebada2aa42076a3f46b335bcd87f22dcfe30b585855783e7060cc955c71166f7258d91ffffd71e2a2aefbb9056476069058ae64f5d8f11c0e2f4ad03d5c2b0f1ca9a60234f5d545569526f667cf1747e5dff662b85d93a884a9f16d63bc61a40ee6a661a22bdbcd343ebfae7b333651c8835cd8fcaba7df1b126a3ee0c5328a5a180857ddc6a5ad4d600bae7b525a6ed673f24d846b71aeaaa02fb2409c37217f3d964497b68793ca62d39b91de262adce0b746efcb7786f8c35900aaaa78363d1890fe0efa083a4a36cf64ac1e20ecd9a33f7acb9c874b9e8ec85c94433773dcac5541eb26622a218c8227a97f73fbb8c0c1f41c5922d4be55c404586a68b2068521f1d865f3ae0930cf62db6a8e6d14a3074087db284a5eddad2ac617c443d6e9a4ffa1714b91984bdf81add45ab59ddba1c0a7448190c3f0a3383ad25870b6b6195383b6d2fc5dbd1894227870bc49028234d4c1ef446d8a1f809df4f33367f47939bbfa942bfefb51ae049184097fa6fa0af3faab52a2fc717862
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138435);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/15");

  script_cve_id("CVE-2018-0304");
  script_bugtraq_id(104513);
  script_xref(name:"CISCO-BUG-ID", value:"CSCve04859");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180620-fxnxos-ace");

  script_name(english:"Cisco FXOS Software Cisco Fabric Services Arbitrary Code Execution (cisco-sa-20180620-fxnxos-ace)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A arbitrary code execution vulnerability exists in Cisco Fabric Services FXOS software 
due to insufficient validation of packet headers. An unauthenticated, remote attacker can
exploit this, via crafted packets, to execute arbitrary code. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-67770");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180620-fxnxos-ace
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?267dc032");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve04859");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCve04859");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0304");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'FXOS');

if(
  isnull(product_info['Model']) ||
  product_info['Model'] !~ "^(41|93)[0-9]{2}$"
)
  audit(AUDIT_HOST_NOT, 'affected');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '1.1.4.179'},
  {'min_ver' : '2.0',  'fix_ver': '2.0.1.153'},
  {'min_ver' : '2.1.1',  'fix_ver': '2.1.1.86'},
  {'min_ver' : '2.2.1',  'fix_ver': '2.2.1.70'},
  {'min_ver' : '2.2.2',  'fix_ver': '2.2.2.17'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCve04859'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
