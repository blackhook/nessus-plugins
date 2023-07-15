#TRUSTED a70d031d36bec0bd88a9da4a5562875b0856c7d41608503b59c9d89b5af6b2642d353793fc6b7f4d83fc59ed608212e761c8d20abd34e5946d392d388eddcb6724ba39f9b310023ebceacd944199a8d6934739002e197113984ad231161efb90c560083b597d1193d62f59d5cccdb05a0a0b13c39022640197f9f1ab835af9e395b62a00fe3e2fda8389f2a5c319694c8d0a313dbbb5b70d4493403002c687960894b85946d1f1dc7c260a6c817cbccb76564b8e18ef091f22b1139720ac7cfb5db3389de57ca0ac232714eb1ac3b18ccf9a035018bb00a36eebfaf364ce6df31fa1954ad1a256849cb56debed02ad26738604ea49e2f450aa5118651b76e5b01cb938a7bb1953f922cd39fe1ae81ebb12e5a3af431c0ae6ca3344d40f9dc26af2e7fe6690dce375f8d38499ac7f690bde27463be40364e848852fc770d554c34de95e868c6c63d103b33c83b73b99763b59bdd25e71fc182e2b990a825a1ec5dfc9a49512c4ea710a6680b0f643e1e6fdc464318c67a6a84964cb8636f390ceb989cc8e5b0ee1cb008b8052f055cfd0676d6e00d36c0bdaa878ec8565657ee5dd819170d3de2867082372d2228ffbfed781cef31d1e5ab88a9dd019109b53397686abfa70ef7703c946068c6dc7e4deb1c21a0699d18d36481db7ca8fce6640e25534dade6efcd80d3fa9e00fff5800bdf643dbd77dcf9b556e163314ba58b9
#TRUST-RSA-SHA256 ab6eca15f8ffdd78a1ca9ee74dce5587e36d95b0e28d62219852894e035cdb4ea637e9884647013232ea3a840298de74bdf5c1a91292dc1259821efecc0ee50d39aac4dc23cb9d65e91abf39af21c0fcddd852f8a87bb967e2907c9aeedeba2a514df9ebc7dec3fec1f5a7d742d2533eb9897eedc979f48dba67079d5eaefb21384c5321708cb588adbf109c95898caf182120c23ab522f01f69d5d8cf96643d73c13ed658a3023e3b003a920b6e1ff872181f563eb355dd5afa856a415ad48e59e09ec4888f875b610492638f3d575b949bef0851ade59c61b4f277e27f0ad504b175480e6284cf9c7337023309d395fbe960e8e6d9ae36702ca77cff7d29f10ac1e40c51b53acf20855f3f5f16a756e0840374fdd0e1961b25de5f87f006413e56b7da258411985e020831abb54dca431f4af5fb1fa0203076785e3122d33aaf0a31774a7b59aaae36e19790c787243086b00fd737f47322a7de36aa40b36cef5ea7374d8f02005462d821640738c044f05bf1d95207020385ffd93df304c79c9758fca7a857de787d292ca53f006e564b0f45fbea3a78bf369cc59edadc6ef5e924c4eaf40b36625e7ef4737a01e56403aee23953d8f527bf091daa2605899e64a6da9bedcdc8527db921337df932ec3d40b79180bfd5f76717e452066c8f5bdd775d076827630e3d3529ac91bb6862ba1e50fe2fd3b58bcefdf6bf5af5b1
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137661);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3191");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr07419");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-ipv6-67pA658k");
  script_xref(name:"IAVA", value:"2020-A-0205-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0042");

  script_name(english:"Cisco Adaptive Security Appliance (ASA) IPV6 DNS DoS (cisco-sa-asaftd-ipv6-67pA658k)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Adaptive Security Appliance (ASA) Software is affected by a denial of 
  service (DoS) vulnerability in its DNS over IPV6 implementation due to insufficient user input validation. An 
  unauthenticated, remote attacker can exploit this issue, by sending a specially crafted DNS IPV6 query to an affected
  host, to cause a DoS condition.

  Please see the included Cisco BIDs and Cisco Security Advisory for more information.
  
  Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
  version");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ipv6-67pA658k
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f09a07e9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr07419");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr07419.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3191");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '9.6.4.36'},
  {'min_ver' : '9.7',  'fix_ver' : '9.8.4.12'},
  {'min_ver' : '9.9',  'fix_ver' : '9.9.2.66'},
  {'min_ver' : '9.10',  'fix_ver' : '9.10.1.37'},
  {'min_ver' : '9.12',  'fix_ver' : '9.12.2.9'}
];

workarounds = make_list(CISCO_WORKAROUNDS['dns_non_local_routes']);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr07419',
  'cmds'     , make_list('show ipv6 route summary')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
