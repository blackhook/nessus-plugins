#TRUSTED 0bdff8f07713da874939f9128702de12d5c62642913d814f83ec828f233cdf754cb1abff10dabae0deea044cddefdd82412e02979ec804733e3d3a8eb72be8ff157b4c98756aa6de1b8251c10191e4d68b3eb528fc39a1486cf2e877ecd1803c1157ac1c44e73f9161a4b6f0dda411d49580bbe52bd7532dc7fc2077716e8fe57b62fae6b6e8aa9f9a5a77d013f41ec5802f5f9e8ea6d4e7085dd22c9568517227a1bafc17ddbf87831e49adadd924117ac0938761408194583db1410ce1974958b065d56db7e2221dbaecb2ade4cc9773218a9f8cd2ff4d3bb72f75c763335032d2fe29bde060c30601e638da96fda7d05b650efadf44b52571793e3eeae88c82c19c55bef886f2c7b950625ed85ab043abca395f115051d8e198e982b340842d8e688aec5fff836e2ad37278d3c6b84737b5d7646ce894b9c6f1365688ce8ac2fd2639b0eaaf8d0f742ee43a9ace22ddc5ef9d0cd716c26cdde2f72d891be7b05a4af6ed7289008198117b0e59d5fac278cb9e4b884e51e5857fe65a1e5b19f9966e537f45279ffd8950260139ac4641bc9fd58aa57427f8897ccaa72a6df04ae083aae2191ea42e0750e99fc896204ba60e8552077e5c7bab937457588a95058ffbf0fa41c071fcbb8031e24aeb4a49c6f185a665dfa9654331e9044596551ccf542ab1d4b37e994c5a30561f1de4e6a116198774b4ba8e3fb9804a334fe2
#TRUST-RSA-SHA256 af77b1e08e42b27e950c9720ed28779bd501baf1d4ca0cb784674cab6d63023387a04be77d5a6520daf084eabd13b96b7cabfd648542b7643b9ce2186a9edfa78a830356dd50e7bef55c07e02326039c11cbf268e5665b0438b236219ad6ad285a3229ef5c031f22568fc0b8978d2158ee8d8ef6da0b217570cdd2c37c8cf5d72efb2ff29e741442c417ee374ec2a1a9567bfe12ed2dd9f01fa9adb89f600c0de33a675454f9df3583e36c1bf4e69b6f3f917294538d5042b02469f91f56cb885e9fd30f0faf5b34dd89378ac50bb546902f2647a177a2239e04b281fce46c0d69c87432722352d60a30460a5ccf7bb0c2350c31846d1bc093ad694aeb06ead65859e689228cd16b000828cc5ac20042c0626f70b575843cc2cd256a471abaafd900d3b467985e1612cd3c0bc21d241f9d6cffeaa212eea3b19ed1493acbbf620894c818d3b51df27fea5bb9272ce967e09cdd3ef41879f9df74281d9f78a7c47c4dbc98dd0cc6f289e7269f16b2d717bbffef2ccf57def38ff9c52c3880ada30ce9077ce3ae9505bbc88c7c04117dccb94b32e4fa86d1f09557fc4117fe89e3794a7b20f4e588c8befb905fd03c77af5b0e4453a4fa420f63b09c09f7cc7762f9829700e73314f23a5d9be20a09c7eb633664ed7ceec2000809ae38340b93888099a82e9f8aabb0d6984ea4098e17c4dc45e04e1b940d2e6f94caa779f0b327
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165532);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2022-20944");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx12117");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-xe-cat-verify-D4NEQA6q");

  script_name(english:"Cisco IOS XE Software for Catalyst 9200 Series Switches Arbitrary Code Execution (cisco-sa-ios-xe-cat-verify-D4NEQA6q)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the software image verification functionality of Cisco IOS XE Software for Cisco
    Catalyst 9200 Series Switches could allow an unauthenticated, physical attacker to execute unsigned code
    at system boot time. This vulnerability is due to an improper check in the code function that manages the
    verification of the digital signatures of system image files during the initial boot process. An attacker
    could exploit this vulnerability by loading unsigned software on an affected device. A successful exploit
    could allow the attacker to boot a malicious software image or execute unsigned code and bypass the image
    verification check part of the boot process of the affected device. To exploit this vulnerability, the
    attacker needs either unauthenticated physical access to the device or privileged access to the root shell
    on the device. Note: In Cisco IOS XE Software releases 16.11.1 and later, root shell access is protected
    by the Consent Token mechanism. However, an attacker with level-15 privileges could easily downgrade the
    Cisco IOS XE Software running on a device to a release where root shell access is more readily available.
    (CVE-2022-20944)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-cat-verify-D4NEQA6q
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05e26136");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74745");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx12117");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx12117");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20944");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(347);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);

# Vulnerable model list
if ('CATALYST' >!< model || model !~ "9200")
    audit(AUDIT_HOST_NOT, 'affected');

var version_list=make_list(
  '3.11.6E',
  '3.15.1xbS',
  '3.15.2xbS',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.6.9',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.9.6',
  '16.9.7',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.1z1',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.5a',
  '16.12.5b',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3',
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.1z',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.3a',
  '17.4.1',
  '17.4.1a',
  '17.4.1b',
  '17.4.1c',
  '17.4.2a'
);

var reporting = make_array(
  'port'          , product_info['port'],
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvx12117',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
