#TRUSTED 4d92e00956cc91e8db96973f1096131df097c0bc2fff4803b027bedca6298ae9f66ad6648697b8e72aff1654629eee6dedc6f956ebb2316b081a3459bee16d4cd6e29d986b3546999e0576b1ac0e0cf7da9798df63bcabad1f4b1c39a368ed1405260f8e6e5c35f5b1513c559cee450baec9b64d565afa632e21e5a84340a045b576ab3cc940ac15eb9192a8198cfcf12d9fe8487a09a25800e9fd78fcc13e8778f4e16d401aa28da6addea5646c449eaf1872051ca7d2caba3afaeb3add01cc98e3355134198720d2eef84e09d2b2f724abfeb653a31dad8adbccccd2b84df0f2ae2780bf6bdc4a555bbc1480c921c4d2071558fd1307f1549fc3d9cf4a71e181d9b7fd694294b11c888e784976e84dc0ffcc5da2b01c1a9d7e5b87152c77f38512eaa5e23cd5f69ee7de99dff3cd8a46e9b4375e9ef13633f9ee49aaf254cddda12a9895c08be13ee7cd1970d0d453f334ef0884e979b93c502e9a2e107bc489f4e0f66d1ac08ca255ce1a1d8bdb78115097caa87270fa7ad189c676f9cb4189815db49ff1f189b91a544db4663430cc1e72f0d97d9f0f756cc1004a67df938d3c7965353b68c85563b7018ebc6cb64954a66659803e3b11d5d4b391cd8b3887822803c71bc462d448d9cde41c0ddca85ec372351046f8f43445a2b64c935e738633c5a8466b6cfcd017ebfc0e072d3c7af4c8617deb1eda38201045d8c2bc
#TRUST-RSA-SHA256 160e4c1bce201287242f8997887c2312f342751738901fa6d5e1d915d3a74897e1f7acc9c99717926832cce505dcd0d71389c884baff39eb1c74fd99b8b8711078c7ceda346db49b6bd8233d1e10cea78855ca51ab73ef83b72d62432363c5e5580756fe12ac8acd1dfb739e76690d0016c0a76016a291c8a8c0ac1d68517c3b9e58e8e539746f455de6a0e5ad96c7aaf3aeadb57c2cd98b2335c8efd2b265b438cc03c42a128c81e234e5ed991c9a71124da34674d64b36bd6e2e8c0987421c18fc774f15d6f12f74fbe13b3bcef175f50df4e97ec5f481f95912697b90d37f189769bfec21012196e6a714e544c59adcf6833b3812998fad0fb00c92c7305bfc8a06195462ca10538b9f52119056e3c0485bba01ed4823ccbc7a971c430e1abd50b5866f48453bb4aed562a2c2f01c4d164ff9e8a105b898d8fc4b9a31ea12266bb9626243ace2ca9205b1b79c7ae7619097f5b9eeb0bfac065c7abc727fb845ca4e0706778820ee6ab8cc19a170990544566c4157524acb2463b278491256fd5398947b858bd9662a2740877f6b8ab8fafce244fe86c784edad286552b9e1ec2bc0b25036c5dac116dfc60bfd7816fd29f3a60ceca970c4c9aafa72a36efa4bff8629b184e9410d82b8d5870129aced6d50230cb5ed4a9dba7dbebfb01d21560834ed40839a9a8efed2558dc6e057cc63e49fb2b69a8cb8748b98b90d64fb
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173978);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/06");

  script_cve_id(
    "CVE-2023-20137",
    "CVE-2023-20138",
    "CVE-2023-20139",
    "CVE-2023-20140",
    "CVE-2023-20141",
    "CVE-2023-20142",
    "CVE-2023-20143",
    "CVE-2023-20144",
    "CVE-2023-20145",
    "CVE-2023-20146",
    "CVE-2023-20147",
    "CVE-2023-20148",
    "CVE-2023-20149",
    "CVE-2023-20150",
    "CVE-2023-20151"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe21294");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75298");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75302");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75304");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75324");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75338");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75341");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75346");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75348");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75352");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75355");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75367");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75369");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75375");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75377");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv-stored-xss-vqz7gC8W");

  script_name(english:"Cisco Small Business RV016, RV042, RV042G,  RV082 , RV320, and RV325 Routers XSS Vulnerabilities (cisco-sa-rv-stored-xss-vqz7gC8W)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV016, RV042, RV042G,  RV082 , RV320, and RV325 Routers
Cross-Site Scripting Vulnerabilities is affected by multiple vulnerabilities:

  - Multiple vulnerabilities in the web-based management interface of Cisco Small Business RV016, RV042, RV042G, 
    RV082, RV320, and RV325 Routers could allow an unauthenticated, remote attacker to conduct cross-site scripting 
    (XSS) attacks against a user of the interface. These vulnerabilities are due to insufficient input validation by 
    the web-based management interface. An attacker could exploit these vulnerabilities by sending crafted HTTP 
    requests to an affected device and then persuading a user to visit specific web pages that include malicious 
    payloads. A successful exploit could allow the attacker to execute arbitrary script code in the context of the 
    affected interface or access sensitive, browser-based information. Cisco has not released software updates that 
    address these vulnerabilities.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-stored-xss-vqz7gC8W
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54397251");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe21294");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75298");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75302");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75304");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75324");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75338");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75341");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75346");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75348");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75352");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75355");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75367");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75369");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75375");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75377");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwe21294, CSCwe75298, CSCwe75302, CSCwe75304,
CSCwe75324, CSCwe75338, CSCwe75341, CSCwe75346, CSCwe75348, CSCwe75352, CSCwe75355, CSCwe75367, CSCwe75369, CSCwe75375,
CSCwe75377");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20137");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-20151");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  # RV016, RV042, RV042G, RV082, RV320, and RV325
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv320_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv325_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv016_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv042_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv042g_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv082_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv320");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv325");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv016");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv042");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv042G");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv082");
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

if (toupper(product_info['model']) !~ "^RV(32[05]|042G?|016|082)")
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'flags'         , {'xss':TRUE},
  'bug_id'        , 'CSCwe21294, CSCwe75298, CSCwe75302, CSCwe75304, CSCwe75324, CSCwe75338, CSCwe75341, CSCwe75346, CSCwe75348, CSCwe75352, CSCwe75355, CSCwe75367, CSCwe75369, CSCwe75375, CSCwe75377',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::security_report_cisco_v2(reporting:reporting);
