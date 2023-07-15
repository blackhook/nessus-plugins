#TRUSTED 1ff19d8e77b0ab4a391a87c70f1ffe9d348ace62a312db612361f035b6b0586c1b20420f8668a05e791232b1f5aa25350f0354d487c6570a7b0a13d932bb32cfe2e2ce5edfa4bf301ab1ca3a324fadd5d16be6be39769dff48e45fc74b43dc44ecc1bf21acb53b03c3e3621adc60186f253f874dbef1d1848ff7d70545b510e6482587e969a786d72aa3ff7b1e59c5e321cec844ad9dc7aefd9af049dc39cb900a3444f05f7f8521be3bcd0d331453e4ac5d456a993df0c75aa3bb5994e8a6940abdc0bd4ae637f9c1137b69ecd3abb71737e3b2ff712112433da41f859499d20a4ad83c66f1dd3071edcfb62f9eca4cb4b57f65c8b626bf6380621c99d0d20eeea546a3bba1e221803afad5e57cf85ff5154d96cd6e26aaaff0b2a20a37613be28bc7c252ec8e98846b5c4d7297cbb84fbbd8b2ddea5d1eeca98c4744ad2abb406470f99b358e73142d134dbd604551314a695b3b3042b600045fe144ebd76162bd01ee4d3475242f88a8d41e04b95c7322a7cada440bf7f8e64d05e3fb44f68fe3fa3f827f221bfe76a3f62b880497a6752a535b0a2d724a5ce5f9bb91390c773c53f4a7c1ca2819cdc9a2fa204e3860f8640d3b000a33054aa357789847692cab2941e7e8dae7cdb54294ce517593512e8632cd769a050c938b39019fd268ada510875036c9855c5dbc70b139dd8a34378ebf0c846e1f79a28c8c409ac67e
#TRUST-RSA-SHA256 2ad277b51379e009356d51dd2bfabcb3f51e41094f31666b9fe1ae499c31a43f98cbbe46fcfeeef385130a763b15b931a3355e89b7715a46a839d35b48a6948e8993031b2305124177feb991b605200c019fe33122abff189af934c6058c555a6e732d2c053b18108619766dd3445f1859e132aad791766dc94ba76724cd74d56d001656d3611d700e2bf74ab64f1f5bfc1eda62d5ef0e63070e11bc36a85c457385a9b380c34348eb92866224ccb2a8fb07ca464633f506fb1e3354868b7850ac810cd45fd9e93b8737566edb42282e43e6b71e8bac4c8f4a8e6655a6709113395634f8d252b92930712e441e86faf083d8aae1aeed6901bffed4dd697c6b11e3fd31188ec809994dd7942b49a2b049309a87e7eaeb96560e19e07d5bc614bf4a41e6c8cf3eb01a327d3dc4a16c8995ec08d617b33efaee6d262a424cc369333d8b915cb471574487548884d1e46f585440018132566885f6d25bf244b34f08979b80866f7430094350f6ba9513302c458636e7cbc7a1145dd338a88bea9cebedbc90d12e5414eff469e396ebf101b60b83412f2a2fb08ca6bf98b0c9d5f7888959cc151e9c7b7e977325fc007f2e5322fb427954b8b62c4c791e9da8e150651a35ff88adba1ac1c4bf0e5a59e00fa678f23804b90979e1086cfa144d87b309cf1b223f7fd8c0cc527ed6cdd85bab72757ce8b2ef4d476d8a1fdcc6b17d4855
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173970);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/06");

  script_cve_id("CVE-2023-20117", "CVE-2023-20128");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe57193");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe63677");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sb-rv32x-cmdinject-cKQsZpxL");

  script_name(english:"Cisco Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers Command Injection Vulnerabilities (cisco-sa-sb-rv32x-cmdinject-cKQsZpxL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers are affected
by multiple command injection vulnerabilities. Multiple vulnerabilities in the web-based management interface of Cisco
Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers could allow an authenticated, remote attacker to inject and
execute arbitrary commands on the underlying operating system of an affected device. These vulnerabilities are due to
insufficient validation of user-supplied input. An attacker could exploit these vulnerabilities by sending malicious
input to an affected device. A successful exploit could allow the attacker to execute arbitrary commands as the root
user on the underlying Linux operating system of the affected device. To exploit these vulnerabilities, an attacker
would need to have valid Administrator credentials on the affected device. Cisco has not released software updates to
address these vulnerabilities.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sb-rv32x-cmdinject-cKQsZpxL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1bc4b1f0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe57193");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe63677");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwe57193, CSCwe63677");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20117");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv320_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv325_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv320");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv325");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

if (toupper(product_info['model']) !~ "^RV32[05]")
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwe57193, CSCwe63677',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);


cisco::security_report_cisco_v2(reporting:reporting);

