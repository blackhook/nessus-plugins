#TRUSTED 7dbab1febd57c1110b6379a37c701bd0e327e7ee56b9e243467660fa102c09ac95c71856eb6c5e0ffd03c4be6d0d805a82637432abdfecf6a64eafbc3cb5a4e416d835691827ad9f5cefc353a79499b3012de162c8b960df048f3d92fea51eb47c27d1e4a12f8bd4824c36da81244badba3020a99fb9d5b57fe08863cbd7a6a5afa22bb8c955fbc4217a6bd94f49556c3c42d4b782af97293691763aab34c396305d4053c648ea492969b8f84fc00b5498ade07b0f7dcf7fa3578c154a5e682ce693ffde2769f41a6be080be4d37dff2b066f9c126cc8df89865dca925cfd317fa81aa97b6e23dc1d5d9e63f47c74fcd7ead9f652b2a193f7b01f3d23305f412d9e6563813be5ccf367b93185f2a39112286325a12140b3814a0c85a2e210b51625bda372022eb49812bb28579e5de191becf3eb1c4beea7a86438468832921bdb5fbaa8a0631e4f14c2c6d3c5782fa1544f3d01a988c0fe69be1996963d6348233c02c8c4d1b117aa829505fc8d3355c53dbe63ecad6ac38da0050690fe0f52db25fb68393c6fb5c05d37ae6a0efe9bc5c0db4e3a43cf6d582cdce350f353adb67860e63aca9538a55a34eb3f7cb540eb4250daacca764f51ac7238cc1e360d65f9970735f734ef327f0e6bbcc300606d14fbca6c5a1de547d130a7f6f0bdc93055aa9ec48d721baa1b85d6fb2c17d73dfc0eed14ecbe92c643fd1daea0a32d
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140212);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2020-3548");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu35999");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-tls-dos-xW53TBhb");
  script_xref(name:"IAVA", value:"2020-A-0400-S");

  script_name(english:"Cisco Email Security Appliance DoS (cisco-sa-esa-tls-dos-xW53TBhb)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance (ESA) is affected by a denial of service (DoS) 
vulnerability in its transport layer security (TLS) implementation due to inefficient processing of incoming traffic. 
An unauthenticated, remote attacker can exploit this issue, by sending specially crafted TLS packets to an affected 
host, to impose a DoS condition.


Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-tls-dos-xW53TBhb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5bd1c68c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu35999");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu35999");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3548");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(407);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_(esa)");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

vuln_ranges = [{ 'min_ver' : '0.0', 'fix_ver' : '13.5.1.278' }];

reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvu35999',
  'fix'           , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

