#TRUSTED 3f2917172e906fe03868ff3a34a806e291cc57b26e611a30265ae0423b7049f6c3b5a32511f4eb5c50e8a968868eecd823dc134b7df9c96d573681fca4ad9e3d8f6cbce704b1f9e5926243e9ff5f2e735e0fe038f863a87739b1988fad4fef3aba9864a23d788f508ab406e9907cfb641a2759d879654c024ebc5c4ef8e85a336a8eb6f0ec28ead7939902bb96ff50759531f621a8b6766c93c2481c2b4dc87fc1448c31d0919250cb52192fde65e7e5f7ff6cabb3e50a55b374304997ed3fd9948953d93f5ee4d7a029f743ef6e94a73c1f00e17db6bee129c36a2ca03747115d2ecc642629ed31fe575c45c7a333e9c44aaeb1a78da94f4b3e664d7b12562541aefd30b8c5c225638a9bb51fdb86dab6536fadb02f9c421c21bf682e38ae4b42e4b84be9a1672c04d470d487168a3bb3065ffde4fd100df70f4b0eae6ed8eb6ba8cfb8fd996c34d44a3119fda23418a9889a5f776a617ab7265d864ca37d10d8b82e44584286b3cfa9511b9926165192cff36c4c24660891826698903528664cd855e284423678a94227d324c63721e1697d62944a845e3a07bd4148adbd4b7986b996d9f9ba094d763316bb399b69de9f9779dba965d562cbfd55513316ebcbfa2ea3277d84968b629cb1811098dbbc96f41e9c609c10c75dbe022fcd7807510659aba4a5f9997d0dac95ed6483073a8497d9a8fa296c84560e196deff797
#TRUST-RSA-SHA256 5391ae4bf0a31ad84993e366a33bb41205212df4f75fe566f0f2ea4ffeb2608a54ff7b204544a5767ed605f1f6747d95a5acc767dcedc6641e8616d22cb79c04630920682e8795dbf83483fa764697bf06ac3076462bceb0c4683a3478cc4c00b27b47b1c65a9ebde94ac0927750283254bfd2940dcdf0678384b3204a387793f35ae1a753fa4046e1729d711f075d3f51e820c7c3feda4d3b304fd73532ebb144f8283d2aa9101db753b28c4bccfdd2fe374c2a3f87f28a99c42831272932b90cb033d1d78f5e193366ef51e6ebf60ab16fc0dd54ced82b0dce48ca1592da4b73c0b4b686ce3ef83a75146d5a640e5ec0a401124f6a8233da26611518957e8e80fff30dac44297eb7d2a949449dbc6cfd9b14fedcc5856137e88c71487c2befde7e9d0fed8c53ddc119f1b8cc9026dc3ab28e5b6c721284daec157c1e7352c4fd1190c30f46d9379806090807fde0ffc06358dc4f51274a634a8c1dd4a3c5d39f80ffc3ebe824e7b97b5f73c8dfdda5bf9a48d80da4ab0af79e0e4b29532c230d1f58d447b35062d057683fcdacf268bd9ff5dab6fdac421306f2452adde1f4ea89d077a631cc7c174e7b7287d27293fea712e5970a5f75409b01f442a4d13e2c134f460540553aea721f4efaf1966a2e64a672eda6be502e61dc54cfe70aaab8b1640ab8373611bd395f7c0000238604f322ffce2f20c9aa44f0540aeacf0a
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159516);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2010-3035");
  script_bugtraq_id(930078);
  script_xref(name:"CISCO-BUG-ID", value:"CSCti62211");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20100827-bgp");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");

  script_name(english:"Cisco IOS XR Software Border Gateway Protocol DoS (cisco-sa-20100827-bgp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software 3.4.0 through 3.9.1, when BGP is enabled, is affected by 
a denial of service vulnerability. An unauthenticated, remote attacker could exploit this by sending corrupted 
transitive attributes, which allows remote attackers to cause a denial of service (peering reset) via a crafted prefix 
announcement. Neighboring devices that receive this corrupted update may reset the BGP peering session. Cisco IOS 
devices will not corrupt the unrecognized attribute, however they will reset a BGP session upon receipt of a corrupted 
or malformed update.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20100827-bgp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43edc785");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCti62211");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCti62211");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-3035");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['router_bgp'];

var vuln_versions = make_list(
    '3.4.0',
    '3.4.1',
    '3.4.2',
    '3.4.3',
    '3.5.2',
    '3.5.3',
    '3.5.4',
    '3.6.0',
    '3.6.1',
    '3.6.2',
    '3.6.3',
    '3.7.0',
    '3.7.1',
    '3.7.2',
    '3.7.3',
    '3.8.0',
    '3.8.1',
    '3.8.2',
    '3.8.3',
    '3.8.4',
    '3.9.0',
    '3.9.1'
  );

var cisco_bug_id = 'CSCti62211';
var smus;

smus['3.4.1'] = cisco_bug_id;
smus['3.4.2'] = cisco_bug_id;
smus['3.4.3'] = cisco_bug_id;
smus['3.5.2'] = cisco_bug_id;
smus['3.5.3'] = cisco_bug_id;
smus['3.5.4'] = cisco_bug_id;
smus['3.6.0'] = cisco_bug_id;
smus['3.6.1'] = cisco_bug_id;
smus['3.6.2'] = cisco_bug_id;
smus['3.6.3'] = cisco_bug_id;
smus['3.7.0'] = cisco_bug_id;
smus['3.7.1'] = cisco_bug_id;
smus['3.7.2'] = cisco_bug_id;
smus['3.7.3'] = cisco_bug_id;
smus['3.8.0'] = cisco_bug_id;
smus['3.8.1'] = cisco_bug_id;
smus['3.8.2'] = cisco_bug_id;
smus['3.8.3'] = cisco_bug_id;
smus['3.8.4'] = cisco_bug_id;
smus['3.9.0'] = cisco_bug_id;
smus['3.9.1'] = cisco_bug_id;

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'cmds'     , make_list('show running-config'),
  'bug_id'   , 'CSCti62211'
);

cisco::check_and_report(
  product_info      :product_info,
  workarounds       :workarounds,
  workaround_params :workaround_params,
  reporting         :reporting,
  vuln_versions     :vuln_versions,
  smus              :smus
);
