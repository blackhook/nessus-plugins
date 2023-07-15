#TRUSTED 613f919fd5d8de42dff24d70490dc121f74a843e3329bbbabf3d567a41bd3600a01d04ed00d710b64988ed8401298f5159b73727bc1c1a94206096868f6a546ebffb97ab9fcecc6b4a68c7d088064cb4b99347f80f65afba770e78b7e46feaa21ef7bcce8fbdcbc03dff012304277a6b846eba612e8c2e9bb8c703083a4e15eef829e35dbeef9571482aefd9cc1b9050a531d72287835e5f9da1a6c54e9a8a5d1ca02ec03a3737d5133431e874bba22d1cd0d08ebd73492ede27c22b4a7b88372de8ddf0fb335e6cc4863f7f95cadcaefc71652f76f0b5eb21bb74aedb6d9cc1835340bc2668ddcbe938a4e6037d9d51c988dd4738f896b19575a98a90175c6a0e29f295969778d0ea198a22828763f9b303ee009c410534e36739805b9e73779f74abde4338608d5bef8d911b746344606e13cbe08c52f806dc5416ea715a11124bb179538e2972669b8e4028d2ae003cde09a03805ab5231b4496081df89e6b55e575a5a3c181c29187150322e1188b5eb95beb4afafb6eaede33169cee273a4ce034bdc0d69973825aa6aeb36f992e752f844871d792ad5bb7ba40bb17dbd1cd4f6d02c63d383e50bb06db5a48a92b7af43e960f307ad6eed6d0d95898a3dcfaa6eff9f807891a5b73aa775a625ff04bb84196f9e0219b1fe86b31227bb8f699ffaeb5ea9073001d2da882d054b233d3caeaecb19a73f1fc0a1489151d7b9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128113);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2019-1747");
  script_bugtraq_id(107599);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm07801");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-sms-dos");

  script_name(english:"Cisco IOS Short Message Service Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the installed Cisco IOS Software is affected by a vulnerability in its
implementation of the Short Message Service (SMS) handling functionality. This allows an unauthenticated, remote
attacker to trigger a denial of service (DoS) condition on an affected device. The vulnerability is due to improper
processing of SMS protocol data units (PDUs) that are encoded with a special character set. An attacker can exploit
this vulnerability by sending a malicious SMS message to an affected device. A successful exploit allows the attacker
to cause the wireless WAN (WWAN) cellular interface module on an affected device to crash, resulting in a DoS condition
that would require manual intervention to restore normal operating conditions.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-sms-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22250072");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm07801");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvm07801");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1747");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list=make_list(
  '15.8(3)M'
);

workarounds = make_list(CISCO_WORKAROUNDS['sierra_wireless']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvm07801',
'cmds'     , make_list('show inventory | include Sierra Wireless')
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
