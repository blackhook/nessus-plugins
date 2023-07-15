#TRUSTED 13a37d0b2f4e5c536130d59fac87c71069fe7ec73ea9b5f5d1c4c82356f38d4e523ca6c53ab0cd0e38de11b0a9739cc236dd855ffba8c30e075206d6e4936f0e98a9e200daad43ac3af16de406c6ee200b89cb6f477bb641d5eef06766c925b1277b7243a59545eead3bbf299378819b23c9aae3c0a6236803d1cd9f8c6b509331ba3cd3ab5888cbca891561d4bd3eaf57b2774bb31ec40d4ef85b937f34bd7d473edf31ac78e8946c9a26e8f14743c5456e30ef720931556852d961ed5756d0b92327306938e8e7b828bfc49a503592a81d66bb576106a8e66d4a5203ea0b5eb0d54c7822ff690bce129e7fcbdc6caca93ef9a37885a05e6b017c8bce04d2d147276aea5c500d4e82b2b1a75449b7f117b6205b232f2ab38382b7e85c5fdfa790caac5aba827c640a5af496fe00451bd0b0999d9ba2e0cc41160b0103547f17acaa3973a496acc009c77048c381f1daa1324a47b334526df539eca1750d754ef5f8479ec5827ec138a940d689e1a25a2bb033447e52f84d0c99d10bc521830249cbf663c2a3f4a440d73da9b292f441bacbaf9e0e1621e502fe91b02c39d6493814c0f3f7e268efd75baadc5b2df4437da9691b6001905110b57113c306502ab956fd63eb7ce6e7fffe4495f3db1cb7e479225af8b0da20363b7f7c34f3eab5605cd959f71f0bec35e88ce3682e0a2ffe7f0052ab3f357d5301a90bb89d17e1
##
# (C) Tenable Network Security, Inc.
##
include('compat.inc');

if (description)
{
  script_id(134107);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/19");

  script_cve_id("CVE-2019-1947");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq03793");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200219-esa-dos");
  script_xref(name:"IAVA", value:"2020-A-0079-S");

  script_name(english:"Cisco Email Security Appliance DoS (cisco-sa-20200219-esa-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance (ESA) is affected by a denial of service (DoS)
vulnerability in the email message filtering feature due to improper handling of email messages that contain large
attachments. An unauthenticated, remote attacker can exploit this, by sending a malicious email message, in order to
increase CPU utilization to 100 percent and cause a permanent DoS condition, requiring manual intervention to recover
the ESA.

Please see the included Cisco BID and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200219-esa-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e2c1c11");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq03793");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq03793");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1947");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_(esa)");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');
var version_list = make_list('12.1.0.085', '11.1.0.131');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvq03793',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
