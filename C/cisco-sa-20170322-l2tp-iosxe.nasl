#TRUSTED 7b553644de9e3e3b3a6980b655c54cbe49207e631c8bb1706a590f3bc3a377af9002300ec55f0207f267ca534484659b7a8169f022ccdc0d71d369c2368c1f2fcfd58211de27156d5f411e2e8bd919271e8207418ab05133e5344e158b1c679ac9cff0e900ec5e17a506db130ebcf8e7045eb332cd90893d674e230a1f0329cea7866f92d64b9c74e1e4cc288bcd69f65d1f13294da2d52c40b315bfda04ec85c36940b831ba81084e10aeebddcd7e2090d88ad0b9dcfbf0ba0c9a879c66ed93c2f25f4216d0217905a86e291c105aeb7f65e982b19e901ae0d922558d7a0970c2f4290f7dc284cf3c94a88b74696d6f41ab4566cf8c6804a011587e3473fee08b4adee87dac521523967c1787604ff3caef590af30a7d70779d571ad678125c93aa6e2343b480e2f6f8e265f5382eee20060c867cb1cd117e305cb4a9a3ae4c7d0caa429bc5187d514b792a8c0890f9259846a2e1addb3f3ca16719ed887ff10c5c0def158a58859f58b078eb84efd562d48378d7388d4a8c7ff0f711624b6711509970a1408323a93814bb16edca9ce8377158b0f60fa4b0ed7306dd521ce67a4e4d7941947067504451d3811945ce5c763a7217ebcb025f7f3a60f5373540c6fc65bb20783d644ac2f83f5f4b18fbf8183626b8b1343c331b35cc62a84eda78438903c93bc24e0ac9f416c44675e5acca757283d869ca21cceeb044e9ea38
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99029);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-3857");
  script_bugtraq_id(97010);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy82078");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170322-l2tp");

  script_name(english:"Cisco IOS XE L2TP Parsing DoS (cisco-sa-20170322-l2tp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in its Layer 2 Tunneling Protocol (L2TP) parsing
function due to insufficient validation of L2TP packets. An
unauthenticated, remote attacker can exploit this issue, via a
specially crafted L2TP packet, to cause the device to reload.

Note that this issue only affects devices if the L2TP feature is
enabled and the device is configured as an L2TP Version 2 (L2TPv2) or
L2TP Version 3 (L2TPv3) endpoint. By default, the L2TP feature is not
enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-l2tp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4fc7ea8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy82078");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuy82078.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3857");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  "3.4.0S",
  "3.4.1S",
  "3.4.2S",
  "3.4.3S",
  "3.4.4S",
  "3.4.5S",
  "3.4.6S",
  "3.4.0aS",
  "3.4.7S",
  "3.5.0S",
  "3.5.1S",
  "3.5.2S",
  "3.5.0aS",
  "3.6.0S",
  "3.6.1S",
  "3.6.2S",
  "3.7.0S",
  "3.7.1S",
  "3.7.2S",
  "3.7.3S",
  "3.7.4S",
  "3.7.5S",
  "3.7.6S",
  "3.7.7S",
  "3.7.8S",
  "3.7.4aS",
  "3.7.2tS",
  "3.7.0bS",
  "3.7.1aS",
  "3.8.0S",
  "3.8.1S",
  "3.8.2S",
  "3.9.1S",
  "3.9.0S",
  "3.9.2S",
  "3.9.1aS",
  "3.9.0aS",
  "3.3.0XO",
  "3.3.1XO",
  "3.3.2XO",
  "3.10.0S",
  "3.10.1S",
  "3.10.2S",
  "3.10.3S",
  "3.10.4S",
  "3.10.5S",
  "3.10.6S",
  "3.10.1xcS",
  "3.10.2aS",
  "3.10.2tS",
  "3.10.7S",
  "3.10.1xbS",
  "3.10.8S",
  "3.10.8aS",
  "3.11.1S",
  "3.11.2S",
  "3.11.0S",
  "3.11.3S",
  "3.11.4S",
  "3.12.0S",
  "3.12.1S",
  "3.12.2S",
  "3.12.3S",
  "3.12.0aS",
  "3.12.4S",
  "3.13.0S",
  "3.13.1S",
  "3.13.2S",
  "3.13.3S",
  "3.13.4S",
  "3.13.5S",
  "3.13.2aS",
  "3.13.0aS",
  "3.13.5aS",
  "3.6.0aE",
  "3.6.2aE",
  "3.6.5bE",
  "3.14.0S",
  "3.14.1S",
  "3.14.2S",
  "3.14.3S",
  "3.14.4S",
  "3.15.0S",
  "3.15.1S",
  "3.15.2S",
  "3.15.1xbS",
  "3.15.1cS",
  "3.15.2xbS",
  "3.15.3S",
  "3.15.4S",
  "3.3.0SQ",
  "3.3.1SQ",
  "3.4.0SQ",
  "3.4.1SQ",
  "3.7.4E",
  "3.5.0SQ",
  "3.5.1SQ",
  "3.5.2SQ",
  "3.5.3SQ",
  "3.5.4SQ",
  "3.16.0S",
  "3.16.1S",
  "3.16.0aS",
  "3.16.1aS",
  "3.16.2S",
  "3.16.2aS",
  "3.16.0bS",
  "3.16.0cS",
  "3.16.2bS",
  "3.17.0S",
  "3.17.1S",
  "3.17.1aS",
  "16.2.1",
  "3.18.0aS",
  "3.18.0S",
  "3.18.4S"
);

workarounds = make_list(CISCO_WORKAROUNDS['L2TP_check']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCuy82078",
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
