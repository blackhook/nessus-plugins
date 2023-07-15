#TRUSTED 0fb6d8af4b8dae00599f7048155b648e974c250fdccfe083a8f32f115a4bb5809fc05c173ec76eeb48e38181e26323668e5f6a7048ab1929881684c0d0e86f2989d320f9d1593ed84fd0088bc7718b5314faba19ca0e7bd724af19621146fa161d9dc7c5cf01b537ede5f28f0ddea46172ed2a87db9112416630184f382f55d773bcea164d481e6598f34dcf9dc698300263ce857f158082e5a669494e131da9eef5b6de75595064f50ecc8aeb33f7c7665b5724d1a43be6f4f28cc03a8f4df5dca58e750788a002f5824536e9da64d626666611b585a50fdbe4f7646ab215cf739b0e644bb07bda321261ea2b14ac5486a009f23c2289af3bd56016936db48b728d025228c52d294ff113ae06d8ebd627a99621068d2041ad2a9c5641c12c7cbe7493eebfb937ff17fe2488235fa6f1f566af2ed088e135c7cdfabcd15adecf62d3c009a2a2068ce459828a75a54c46ac2e42c89e803629b1548b01966b20a8d7e1afd830d628a015fad8e9520a552faf421a86ce536992ead997ef4f96bc54e9403c4f93c2faadca3de4866263e77f5df345200f153f064fec8454af3952f60ca9776e8a8890f34eb27f5c3cea4388acdfa8633a9d5b2ba4e617bac9f1f73b985e5359e50ebd02215943e673a7b8cc2e13fc869a1a0cc138d414be44e39909d9f60819a0b0d725ff12426e55d8e1475bae53bfdf896f2b9c8f29f4fc8f08f7
#TRUST-RSA-SHA256 14ef81543828c616657cda84a55aa710ac9261d892c8e0813a7ace97f32fe8d9e341b4c668965045344e04f6da75038299793b0548abb185384d53b2c87dd0318e2997438484ca03a0733787dff36ada87d9dc64457ddf338547870c5d336a2be5ff25de96a4cc34ea5cc36723ab9f710be29024fc6794252654d48d7c16c5d7b210e8f272b0a700660deda1454e70ba5bf1986c838fa99eee8aae2743f3295c3b26c7fbf78d05b57a90e8eca366778ed8c05eb3e3cd44c1e33642f3e16838000a89514e36b724eac51a00af3d84c904fccf3f324a5c7e0557857bf61d9dc7d1c2bc897a55a52ed98a91772a4af80d53fc870b372d857d505f239efb1e4093fb4bd8807f797af008f608832fc5fdc7d51d78a89c133a84c02d78040db3f271e8105026dfb38f47433f66df90af4a2ca2635b97c0c136ad1af8ddb62c9cdffc7c12085911c1a3cb125270015cd16fd8990024390d9fb2cb25ebecf1544325d439fe4b1bb37fb3de51b621bffa6e4b2db7229e07b6eaf3e62ad125490d26a3aba7b6a86fb0ff6c71198918a54baca4444f4e96d6fdad125f9eed17f4b79db35b8c531343025d817cff8add183197579ddfd724350e16b1c10971527fbde12e63e5e15a80f73ad806030845bffea0069538809ca9b6992ee0603cf28a8fe5c0a4431d6a293a417054437535ec967dff212f95aa99e339b4c6d4e94cf7c553b0c266
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166678);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/31");

  script_cve_id("CVE-2022-20952");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc54898");
  script_xref(name:"CISCO-SA", value:"cisco-sa-wsa-bypass-bwBfugek");

  script_name(english:"Cisco Secure Web Appliance Content Encoding Filter Bypass (cisco-sa-wsa-bypass-bwBfugek)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Web Appliance Content Encoding Filter Bypass is affected by a
filter bypass vulnerability. An unauthenticated, remote attacker can exploit this, by sending malformed encoded traffic,
to bypass an explicit block rule and receive traffic that should have been rejected by the device.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wsa-bypass-bwBfugek
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1133569c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc54898");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwc54898");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20952");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');

var version_list=make_list(
  '14.0.1.053'
);

var reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCwc54898',
'fix'      , 'See vendor advisory',
'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
