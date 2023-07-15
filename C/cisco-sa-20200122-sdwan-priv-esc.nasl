#TRUSTED 2ee39e2ace63174e2b2248e6465b52399c3af38317a8603acedb44cdf93ca2192d3a30825e334e8b6c349e148348a96ae356b3d896f30ece2445c49fce721139a4b11426d812a91103b9b223c9362be6f49e5561d6d8fc1539159d6b30751413346d4026b729fec7e04f52490af2bb5ef8d051226790aa897dbb409e54ba9d50c5f701042ee8cc970266b0d9353b08eb6946ab2eb7b88adeb5369c2d9b5139ada71a00df0b10b12c0bf50b350058de35bc0ad3349422fda3d0f5ff0c6f9bec79673b3be378beb85c38e245bce9d6f9d8f20336b93812bb8feec403bc23d1d9236cdca9fb3a01355463e57d5ed69d085701961656f82c5cc7f05325454c8be7ea02b13edb00accc627f08785a29783d66c089bde0c19a1a9120485b943a45334b7dbfb8469586998ae07987a0101900d09239dac37c3f59a3bb801f6c9b8201e1dc06d8fdcb0d2467505c63c841fd262a527f61a9c7d1903dcee3b198ad3c1daba36629837987f785c5949873f5a34c5e56e186ba74e2cd1744f0febd5e8fa49e44bdaa6c9d0f5cc296ffc4e39a0e415d40bdd6bbfc9b4e972f02379e1d8498c5c120f0231ccef759b0073157582f7cfd60dca652a3aa2821695b7725249cb4351ee5234cad8e6a0dfffe6032fe9b4297183c96f483db00d6a5f9fb5b855fd5ca6039597a3295977e3e4de32cbd115b03533c2f827f2554ddf3fa1c766fa351f3
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147732);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/15");

  script_cve_id("CVE-2020-3115");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr00305");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200122-sdwan-priv-esc");

  script_name(english:"Cisco SD-WAN Solution Local Privilege Escalation (cisco-sa-20200122-sdwan-priv-esc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by a vulnerability due to insufficient input
validation. An authenticated, local attacker can exploit this, by sending a crafted file, in order to elevate privileges
to root on the underlying operating system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200122-sdwan-priv-esc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c63ee773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr00305");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr00305");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3115");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_vmanage");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver':'18.4.1', 'fix_ver':'18.4.2'},
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr00305',
  'disable_caveat', TRUE,
  'fix'      , '18.4.302 or later'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
