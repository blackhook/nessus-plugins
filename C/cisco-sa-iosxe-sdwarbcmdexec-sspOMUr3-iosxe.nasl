#TRUSTED 715fb62e949f05ec82064ef6ef5fb36f685390158aee15ab780e34eca8d9846c189591819b5d5a20e5c277a36efd88997ebaf3b95a03afd31b34bc76fd86407b5d952e1cac0862a17b528eaaa417ded58c2fe560591294a6819389e414f9667ae5a72a1eb57ff36aaaac8f739ca23196b22a9e7792fdff607a0eb4b37c8c04af5c43c9299e9744abd6ee6104b2a2cc0477b324e0360ed89b5cc23e227c48085d5b3651a598f6dfe28f170b0de36e674876e7ee48e4d142ea5f8201677dd51e5b5d611827a56beb4df620a667ca2b22149cf7bd60061fa6884c5de9d8b3f5b16ca2d574dac968e114c7d7defe8ebf9fc442070cb3ac16517b962ffbba004456df66babbf2cb914f9f02f9d3eb7bb6ea8429d1ec78c65e57d3c1c0f28e2779b10d9a6d73fe2ce473b07ee46859e9efc032cc6241a9b9149c2ddc03b2df0d9d7b40eaa31b522df69c559a321ae2f2592deabab788e7b3e9d977d79e00d7038fb7b530b0e9234554bb7f3d033f2b9442d9bab64a27e408661f9e333cc9d62a37151ba098cb8232e025811712b2aae4724f6e0c950713a9fa3a3a57e5f29c308e54bb27a4a7cdebaea701d9c80cf4250ad30b40c40ad42e47f9134c87feaddb934fdcbf7f8b93d78cc5fbdb78f6af683f5f2d5e3d49214b2818538d58ab8e59bbf713a927cd3422314194cd00a08baac44a5773ee505b8a8eb268883a04a96014ce32
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151374);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2021-1432");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu50633");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-sdwarbcmdexec-sspOMUr3");
  script_xref(name:"IAVA", value:"2021-A-0141-S");

  script_name(english:"Cisco IOS XE Software SD WAN Arbitrary Command Execution (cisco-sa-iosxe-sdwarbcmdexec-sspOMUr3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the CLI of Cisco IOS XE SD-WAN Software could allow an authenticated, local attacker to execute
arbitrary commands on the underlying operating system as the root user. The attacker must be authenticated on the
affected device as a low-privileged user to exploit this vulnerability. This vulnerability is due to insufficient
validation of user-supplied input. An attacker could exploit this vulnerability by injecting arbitrary commands to
a file as a lower-privileged user. The commands are then executed on the device by the root user. A successful exploit
could allow the attacker to execute arbitrary commands as the root user.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-sdwarbcmdexec-sspOMUr3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ab9978e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu50633");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu50633");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1432");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model", "Host/Cisco/SDWAN");

  exit(0);
}

include('ccf.inc');

get_kb_item_or_exit('Host/Cisco/SDWAN');
var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# Affects Cisco ISR1000, ISR4000, ASR1000, CSR1000V
var model = toupper(product_info['model']);
if(!pgrep(pattern:"ISR[14]0{3}|ASR10{3}|CSR10{3}V", string:model))
  audit(AUDIT_HOST_NOT, 'an affected model');

var version_list=make_list(
  '3.15.1xbS',
  '3.15.2xbS',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.1za',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v'
);

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvu50633',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);