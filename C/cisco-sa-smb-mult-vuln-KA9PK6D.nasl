#TRUSTED 8f76a50fcdc01be812ced3239b19e458053404e4c5becd40aa7b3156f4c423e8ff385d621c1c825c9903d40ff023d1345ee0b4818439da4f97f89e2b8e95e8c887eaa9ff911b5b0c3419e2b971dac79d617e3f870855c19e981d6e1d3295dc9c3f998fd2574f014981da9911bde9f5c22e473e5ace5ed488fb3b1c533c1a6ad5e5b791193306e225778990bdd3f2ffc4a717088b90087e05f6420548354876683c323ac281679bc20a8b0f0db0a38abd3285ea0eb39d9de747f74a629823a56c666e4d2c209b1a202bc547544cd95f93e1ed840ba4c35719d72f685f35e261d67f7a61012fa37b3c3aaa5048c774426a05ea3bdb4fe782cfd4cef409ada1bc8512fbff9a8a3f6278519cec7ee11b9f7bcaeafb0442c6f4167b2002a61cb1bff87d108bfd7ef690400dd7b0ed13c76f0c50640051ac93b3de8b134058cb0ede84b8af981e19e491834d94a51141b6fe99168cda48b7389a412e5944351c947666cdf95620c8f7f3dd3fc813af42914a81c511f2692dd9b1ea70fb0c52a4d98022a533905e38cf6430000ea262b9d0e817a8276caf3786c0fe5c6117d454dfe0900ece7d47a75898f0e45aef5b138043b5baafc31a9aa3fb8981f611f347f2200ad49c0c656c925e321d2514191dee4db6a31da208e0241f7576b0e0b3162c052b82524295f2b7706bdf74aec98dd296ee73198a5c26b3eee601ba1d1ebeb935c6
#TRUST-RSA-SHA256 6b24cd85bdf12da2aa1874a62008a24b181874b070898118d6db221ca4ec86073d395b8630a58cfb6de07f3cfc25333dfea85023df9239a57e5309263827a563d80d112f5ad35f412a78ac352a1b53a72d82243285066842f03dfb783c6036c2f6ef99dd08d8ae09ce8609959ad045bd75a409adec6947c166e0cc5f8867c9ce1ad7cbb4d14472ffd3af151228e47966c24e28cb8e3216abc0c23436251afeae759f6673a90f32d291f61bcda2c67ab736d48f386c7a48f884c67a1634ec79b63f0c9fca624f814739e72f71e084d20251b8a06dc01630f21d05e630ce17d08b4236a2bfa67e27524101bb78409d013af034cfbf331d051420ecac1ca37f5e1848fff469a14ec8ea348e928e83914da9b861e0f0b337059a343457ce84cd44190c890214fe0721e3fc8f4387429b38fa2b6b69d506d809ef4d28b4007dcc25f7fb150fd13e3b3122c88bc5b22c594fb887a5c472498fe7dede7e39074e21ad603d6ab10469d21737059b076bb115fd00ddcb2e0f511515194183119ad53b4822bbbaeccc7b6a9eb58f52e075110cb99078c5d609dec55a01beb8ea472036eef302d535434ab18bfe7d16e4e6cab6430cc08955882f4324f9426aa516f5f5bddac3dd524392b30c3939f8d7bd4c1fea09f39fabcb5e72d11fd4cd25d55dfbaa949cf69fba8a69732f5c389e72371b29a4aa60b7cc71f9a1369574d9c1df4fdd82
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157361);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2022-20699",
    "CVE-2022-20700",
    "CVE-2022-20701",
    "CVE-2022-20702",
    "CVE-2022-20703",
    "CVE-2022-20704",
    "CVE-2022-20705",
    "CVE-2022-20706",
    "CVE-2022-20707",
    "CVE-2022-20708",
    "CVE-2022-20709",
    "CVE-2022-20710",
    "CVE-2022-20711",
    "CVE-2022-20712",
    "CVE-2022-20749"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz88279");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz94704");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa12732");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa12748");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa12836");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa13115");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa13119");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa13205");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa13682");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa13836");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa13882");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa13888");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa13900");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa14007");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa14008");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa14564");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa14565");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa14601");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa14602");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa15167");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa15168");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa18769");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa18770");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa32432");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa36774");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa54598");
  script_xref(name:"CISCO-SA", value:"cisco-sa-smb-mult-vuln-KA9PK6D");
  script_xref(name:"IAVA", value:"2022-A-0058");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"CEA-ID", value:"CEA-2022-0004");

  script_name(english:"Cisco Small Business RV Series Routers Multiple Vulnerabilities (cisco-sa-smb-mult-vuln-KA9PK6D)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by multiple
vulnerabilities:

  - A vulnerability in the SSL VPN module of Cisco Small Business RV340, RV340W, RV345, and RV345P Dual WAN
    Gigabit VPN Routers could allow an unauthenticated, remote attacker to execute arbitrary code on an affected
    device. (CVE-2022-20699)

  - Multiple vulnerabilities in the web-based management interface of Cisco Small Business RV Series Routers could
    allow a remote attacker to elevate privileges to root. (CVE-2022-20700, CVE-2022-20701, CVE-2022-20702)

  - A vulnerability in the software image verification feature of Cisco Small Business RV Series Routers could allow
    an unauthenticated, local attacker to install and boot a malicious software image or execute unsigned binaries
    on an affected device. (CVE-2022-20703)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-smb-mult-vuln-KA9PK6D
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d880707f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz88279");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz94704");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa12732");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa12748");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa12836");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa13115");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa13119");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa13205");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa13682");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa13836");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa13882");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa13888");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa13900");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa14007");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa14008");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa14564");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa14565");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa14601");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa14602");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa15167");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa15168");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa18769");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa18770");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa32432");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa36774");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa54598");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvz88279, CSCvz94704, CSCwa12732, CSCwa12748,
CSCwa12836, CSCwa13115, CSCwa13119, CSCwa13205, CSCwa13682, CSCwa13836, CSCwa13882, CSCwa13888, CSCwa13900, CSCwa14007,
CSCwa14008, CSCwa14564, CSCwa14565, CSCwa14601, CSCwa14602, CSCwa15167, CSCwa15168, CSCwa18769, CSCwa18770, CSCwa32432,
CSCwa36774, CSCwa54598");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20749");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cisco RV340 SSL VPN Unauthenticated Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(77, 121, 269, 285, 295, 347, 362, 434, 552, 754, 785);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv340");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv340w");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv345");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv345p");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv160");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv160w");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv260");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv260p");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv260w");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

var vuln_ranges;
if (product_info['model'] =~ "^RV(1|2)60")
  vuln_ranges = [{ 'min_ver' : '0', 'fix_ver' : '1.0.01.07' }];
else if (product_info['model'] =~ "^RV34(0|5)")
  vuln_ranges = [{ 'min_ver' : '1.0.03.24', 'fix_ver' : '1.0.03.26' }];
else
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvz88279, CSCvz94704, CSCwa12732, CSCwa12748, CSCwa12836, CSCwa13115, CSCwa13119, CSCwa13205, CSCwa13682, CSCwa13836, CSCwa13882, CSCwa13888, CSCwa13900, CSCwa14007, CSCwa14008, CSCwa14564, CSCwa14565, CSCwa14601, CSCwa14602, CSCwa15167, CSCwa15168, CSCwa18769, CSCwa18770, CSCwa32432, CSCwa36774, CSCwa54598',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

