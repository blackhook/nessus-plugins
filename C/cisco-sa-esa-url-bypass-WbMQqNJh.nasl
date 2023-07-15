#TRUSTED 4e5fae52caf25caa28985298e724a31e088a313748198a2b1364336df4b26ca84495e62df72ea01968dc6db4ee325b9a4edac43e9f8086fb56cdd9da4b8bd03619a97a4a4da8f00b88150745dcf38f73c6e4b9ce029fb57f49119ce1dd06dfa7b96ab7c68cd0d96aa206d508c12646a1497bdb52f3ff60423065293f7258ce2ceb329609d087e2070aaa77803d1f3f778e8f2bffdc3e7509e16dda48529e905e52971def423784322615b099ccd2d4e49ffd781d14b7d28d7fcece9c5c3b10c2789f90299a4864558643e6ff30b58bc55504db6856e15dae1b8f9bf34cf4b663f81ea3f88b1789c3308bf909527533f4729dc09c687cd4003b9407ec279d4a6535512b07beae78cd39da4fb6015b6678613c908e58bf2db6db40f932296d3d462fab5496540ccebd9f4ace82e43009aea607946dee54fd98d035ee823a40bfba4b952bb9d0f2612cdca9edd9c232702a3ce406ac9aace698a0d91c2ee9fbd7dd371ba0cbd490064603f3123eaa56ef3518e7d6588df64e97505d0241a1f46dcdb16321362d4859ecd15eac0764333de5cdb5ee319c6a8e96b5da515abb9434cd7ea0915afb1122b6f369be794332009fce79c1d1e5337bc6d67bc64ce7c3f6ff884274c9207dd63589ebc5437dc6e9aee683ef0b3c18a9890cd68836a7722846488bb88a18873444a1e17a073e2b714a085f9fb6e15b269e10f5093b815fcf8a
#TRUST-RSA-SHA256 113506509b7c5e7a7846a12e9ab87dc3d5aee96f06c03abcd30c2b2c9f01fe1f735cb5c2acaa6d2f66439f8cdbb68319307e7e321afb19c51df3cf13581c2e7569ea1e97a6915d21c89ecd85c21e001b8a77faa39bfdf647551ca94987a897a4528de7f1b4f8a1b3086fb51f4c76277f52124c5528519836b39db78828e174e978fe68145c80697ca3bba79dd4beba463b883a4eb782307ddca7a1c04e3d47f72e2f6fcea853a4a4df7fcc493a5cc585c27712a0191ba7502d67329389edb61e4d89dc413284a974550c21672fb53a560447f24508ab048a66f90479114198bab39396a306303f1162ff15399e696c97acaaf0b3e7b1ab8c024614d6fc5ad4bdf1a96fc1411a73e733c56c588a6278fd4322ff55df5beac949cc7fc3222c0f38574ad4710a204e90e3d856fbe186c365b324c21e41ab1560863054413283ae76e168ce4d3ff783f7e8949bae55d5caa98648359ccc90878ebf75ae187714417a33d856b597ccff33514086b95d70ca9bfb3c6398fe8d6dc25dce1d1e9bced476443c29338b5fee27106bc4a85114c0e861dd2282d71ba7a19e43a4c8a5c71e0571fd98487672f1d2161a0a5fc8830ea5bb1ca0a2578815c7c0688a97080823dd92a9edb69a7a1f776eea786c0afef639db4699f9095b3f4bcda0656a76f8095e9bfda2349fabd66f0d5330fe0676d87a4ceb3202e0fdbdce73dd3d489304075c
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
# @DEPRECATED@
#
# Disabled on 2023/02/13. Deprecated due to non-exploitability.
##

include('compat.inc');

if (description)
{
  script_id(170894);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/14");

  script_cve_id("CVE-2023-20057");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb58117");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-url-bypass-WbMQqNJh");

  script_name(english:"Cisco Email Security Appliance URL Filtering Bypass (cisco-sa-esa-url-bypass-WbMQqNJh) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance URL Filtering Bypass is affected by a
vulnerability due to improper processing of URLs. An unauthenticated, remote attacker can exploit this, via a crafted
URL, in order to bypass URL reputation filters.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

This plugin has been deprecated due to an update to the advisory stating that it is not exploitable.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-url-bypass-WbMQqNJh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f6b90f4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb58117");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20057");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

exit(0, 'This plugin has been deprecated. The CVE is not exploitable.');

