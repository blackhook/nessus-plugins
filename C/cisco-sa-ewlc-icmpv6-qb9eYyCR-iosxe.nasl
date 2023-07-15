#TRUSTED 1ade566c8238e7836724e650f41988d2bf6e3c0d587ce8113aa183a2bb970833e1c0170f5e6196d11d9b2390fdd59ff57f998ae4258023a2023eeb79fe97ad988b70a8dc08cd75dadd20222c0c6294e9f371ea7b47a20c18635e66aceb490e4f28d9107199083200ca828f7d783d1a7c2bd4bf25298cb8416e3a3a7c541760de9c5694dd8c965b5e1c6a6eedbaba591ec394e93da9ecd4df6a0d18756c48256940ce8b80986615bfff3f7530b268a621638c3f2232518ff7503616717e79284cae9a4397510c963b4e6696f382274cae32aa4496e2cd0a2452d12e57ab7fa9dde40de5b43ea4ed5c49b2809bba4f7a7644b3941d6697c5ba81da56745034d85ef54782c4d686a1c7d4ff94d316b45081546e7642b8f2aea4faf25f37cc83d4cef6f713c3294780b691411a26148d4be83faa7aaa4a81c5754944ac3387ecbaf2305622260a58f1ad4c727c5cf0feeda5bbbdddd9c7b1df9f39a84b102177c8f5c7c8a640afa98cf9565d5895fc9157200827a535c5bf7dc324338c5ed81d72ab2f807037d7476477a48677a11110fd59cf95d4b2cf8e2d39a67783236a129a4a21a591d2955b67dea45d31592b02bcc3aa3d5028e9c7aad7ec1c3d239d3048db79c45b6e9e1ae268263a4e96613cd24e0025932d3a1db318720ca681869201388c83970cc9976d1e6ce42e9f78349528b28b3e8f748290870075fd5df4d7919b
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(144197);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3418");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr07309");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ewlc-icmpv6-qb9eYyCR");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software Wireless Controller for the Catalyst 9000 Family Improper Access Control (cisco-sa-ewlc-icmpv6-qb9eYyCR)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Wireless Controller Software for Cisco Catalyst 9000 Family
Routers is affected by an improper access control vulnerability due to an incomplete access control list (ACL) being
applied prior to RUN state. An attacker could exploit this vulnerability by connecting to the associated service set
identifier (SSID) and sending ICMPv6 traffic. A successful exploit could allow the attacker to send ICMPv6 traffic
prior to RUN state. 

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-icmpv6-qb9eYyCR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a00821e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr07309");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr07309");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3418");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = product_info['model'];
device_model = get_kb_item_or_exit('Host/Cisco/device_model');

# Affects Cisco Catalyst 9100, 9300, 9400, 9500, 9800
if ('cat' >!< tolower(device_model) || (model !~ '9[13458][0-9][0-9]'))
  audit(AUDIT_HOST_NOT, 'affected');

vuln_versions = make_list(
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.12.1',
  '16.12.1s',
  '16.12.1t',
  '16.12.2s',
  '16.12.2t',
  '17.1.1'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr07309',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:vuln_versions
);
