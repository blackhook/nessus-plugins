#TRUSTED 997837c5e9827bf50134b66fdfe7b815b0be983a21ad96f7425649e3de61422357774a426da25673d62aa28ee7575d08272182f804e10a1a114846db4327537a3827042884538640deb54e95781e9ce5c8bf2ea7d9b1ece042679fd5516e25c8edfd2cd722800d757cdb90494be70ffdc03b8af226a6f720bc023751079e7121bc42a3a198013076191c1295bf5bf64ccdc46cb4a0a419332635f45097f2d54cf3ba4c3598327cf07cd3dee1db17eef0b677e09fcb57d2a6e0ca28499cfdd90d23d1f89b958ddb8e516d1e79ce7573c154ad03ea0a56dd3ff8a118e93a2b27a4fa0735c0e1173370635a0dde37743592c9989fc900119a14f878db72cb6c542a0ce4317c6a5a666321b41687b663ab0e1a5fbbab32cfea6d3623489a6ac9221cf60a4acc290688b05d736489eae9a9d93eed73da469eb08a121770e83f32c0bacabce0e7dc9fd10cf9ccf4ba14c0e86a5041b8aace7d6a4d6c307e90b46098c2e3af5a8927c532a630c778f1a3360c0d9e69160e219bdd0a77acd9e85c9710951a626a5786dade637b60b47446ddbb19649bf7e1d51efac9de4aa1eb43f227690a9b2b0fd2330bddb65c334fd0d487e034eb678f5703f71216eb1f41d24b9badce064cca7c4bffededc5afbc2b807bf7d40353331057ad92d76ca0657f9176aa1ea504d7f4dec87f015bd5a4c7006e670d962e09c42ed0669c5bc72c4c132e81
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147652);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/12");

  script_cve_id("CVE-2020-3405");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt72792");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu35990");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanxml-Aj4GFEKd");

  script_name(english:"Cisco SD-WAN vManage Software XXE (cisco-sa-vmanxml-Aj4GFEKd)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco SD-WAN vManage Software installed on the remote host is 19.2.2 or earlier. It is, therefore,
affected by a vulnerability as referenced in the cisco-sa-vmanxml-Aj4GFEKd advisory.

  - A vulnerability in the web UI of Cisco SD-WAN vManage Software could allow an authenticated, remote
    attacker to gain read and write access to information that is stored on an affected system. The
    vulnerability is due to improper handling of XML External Entity (XXE) entries when parsing certain XML
    files. An attacker could exploit this vulnerability by persuading a user to import a crafted XML file with
    malicious entries. A successful exploit could allow the attacker to read and write files within the
    affected application. (CVE-2020-3405)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanxml-Aj4GFEKd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d52bf6b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt72792");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu35990");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvt72792, CSCvu35990");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3405");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(611);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
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
    {'min_ver': '0.0','fix_ver': '19.2.3.0'}
];

version_list=make_list(
  '19.2.099',
  '19.2.097'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvt72792, CSCvu35990',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting,
  vuln_versions:version_list
);
