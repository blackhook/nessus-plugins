#TRUSTED 08811e212c17d429b31ce2bfab3b74a3adda329504e8dd09f9d4bbd0af2f8b6c2bcb583076072497a52d75a364ad073615f8d86d679c51e31dfef044509f37fae473055f5e194ea6542b117e003014dfe523fe100138a0ec1cb5c24c41bed5f16874fde594cccb105161ca193c4968cde5f284d1432e0aad5f48430e6360740fed110f05a6de8e908d5b480b1e993669d97040c922de635753d0b670886db8571dfd49306db64e2a8ef82381181145cc58ca9d103ee0d3892f3e8429a3e88a9d5109a38106e86cca50a8ace4213a0eb8c06ebf76174086a4c7764246381fcafe1bc2c84e9d064ebe37529ae120109ae2ba23935a27d2b8f313ff2512bd02587dc229dd2c1c0ec9c4af37d82a5255bb85a9546a8f5e80eee3048fdd67ec79fc71fd3b5aa6f65d9b1bc4423dcfc88f23035cad436ced05e8cfec88146739af8227f7d456cc3b1dc17052cba3d39df92f1cc49791e00b84a3ec4c988d540104c7a4e6c499e2e798ef730d7358b45d9bb9fcc70581afdacdda776604a99995a3f4a61ca35a48bb066b73499f7b700c9764c654baec16baf0b1acd708a7b7385b8680e60becca35c0e2ba149f0dbfba28de28098117859ec941d87378944d76ee47e21f8d2acbca6fdb94b91a7bb5807b3d0a6f5e20ad95b7325265458c01a13b428a10b91c8fbce42c4775780a40debfc6cb4b3795d40d8c0953b1ff55596ae67b51
#TRUST-RSA-SHA256 22f6db47351b4cfdc76cd3e181dcef0015fda36e9373652411b8269252341c3843ac1c4346f52b4e089ecfcb498f93635f8079a6bf48e4489d38c4189b337cb71d1370daf3e70db43b88a81f7024e83181b0990305a43072988239c2872b067c1b06ef5140e0bd4ac8813c2679600e480005443a02f3129ea32b712cf07dd882aeb2556e6677e5b2b34adfef7b42c7b3bd90d4f1e39b803e21872c9aa6a214158be68e268f4e108a378fdb9398891da2e2af0cda42006beba36f5feea4c65ea502e659c0fdeeba0433433db8a2e06b36cb92c480f415efd01a2efc33837f08884431390036d84f892ec8eccafffce276ae779c9dfadb7f0c645a858941405485eb6d3af19c1f83c0c58a18ceaa1f4e39d333c942996059fb2430b0126192cc4c291851a7754fd3121b43063a19c785bc662caac0917caab72b1289a235db21419e6535c6227f810bb09ba5176ca3aa77874e25f7c6ce9ba7292f38cd48164867f24460a9201d44251bfdb1d0f3de40eb227104ad96db6b1fc4b4ad67bd3064a64deb5c8a3d651edf4dc47e30f73a5a3e331cc569fededb7c433c42d59ae01a3530318693040b61ad22ca992e967030501c82e1e3cb822731eabf93f5a3614f2340e9d0da5e27b2ac65a808982ea0ded76c70765cb7df5bff7f5538855bc9cd75cd1b9fb0d33c417a6c5630420d276f1803185b347a8283a9debbb6859e15c657
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138375);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3306");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq41939");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-dos-qk8cTGLz");
  script_xref(name:"IAVA", value:"2020-A-0205-S");

  script_name(english:"Cisco ASA Software DHCP DoS (cisco-sa-asaftd-dos-qk8cTGLz)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by a denial-of-service (DoS) vulnerability in
the DHCP component due to incorrect processing of certain DHCP packets. An authenticated, remote attacker can exploit
this, by sending a crafted DHCP packet to the affected device, to cause the device to stop responding.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-dos-qk8cTGLz
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23cb221b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq41939");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq41939.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3306");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  { 'min_ver' : '0',     'fix_ver' : '9.6.4.34'  },
  { 'min_ver' : '9.7',   'fix_ver' : '9.8.4.10'  },
  { 'min_ver' : '9.9',   'fix_ver' : '9.10.1.30' },
  { 'min_ver' : '9.12',  'fix_ver' : '9.12.3'    }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq41939',
  'disable_caveat', TRUE
);


cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
