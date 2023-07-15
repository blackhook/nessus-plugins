#TRUSTED 081ff8779a5ca2073887ce3faa8a0474ac515a6efec5886ccfe50570cc8a24a5b5d740ba27979c2b2eb598a80147ce4c865420192ffe0735cc57c1b5658d5b3b6b70f96e5bb5725def28ee0de056cd38abba2c650b73bb361ecd042a942864d017390ce584bcc248820caaf2707a379c0343348f244c79d770dc87477ef12c9b8d9cacc31ed6e6b5a3d99536ece9ea29c668b02081f0fd3d4a7b26807e0396cbb9794b3cbdb0598bf218cd292784910837187e384a72832ea6e401934c4c9ded76e9ace8a05027b1665f9794bb941a5fe3b324ebed5b1327f73a74fc6d88b60976c32beb6407d3cf4661276f2973d33c5ae131fb2e615c8f20f48141a4370f6d8149b354872b15e9e06d276b203360c58519b70849c82e5cf8234ff9c88ff09ba402ea480576d000a909e798bb0b54f258f77c0bb09b6693df89605841028798abc3f03fa2055971fc7f9cde8420bfecd7a21ec19ee85243f33f9f4939bb28ef1012dc78a87fc4d9ba7d77c890804aa94f6686d9ea0acfea84e7dcdd79b1ada4d9c515ad57dbdb7399285750a518b381d23570dbd63395491d6bcbec016c1d1c7d2418c2e32850095e5dfa7c7a6dfde2de78fb4ae172f97e7f820d0e47d14336ef61b4645b9690c5b9398f0817f19c3380eacae95adbb50f457a71f594eae7e340f4db46613a77e313e90cda81ade36bb59aab1db34542b33e245a1c389427bf
#TRUST-RSA-SHA256 a9f7d9d580a05cfd9914d4a87871937120739cb1aac0332992c1217d336ff0fe96b369f61e2564dc37b318569b97fa5575ed981735f27672b07fdc3e614d373b434528d8adf6d82312e592fb9a88f2a7fa95ea5e9b46515f04cc83999821f29c2ad08fb872b46231cec0cfd1a3e978bd29e2eec1a13a6b6395923504bd4259d191585ebf0a417a82d6643bf5bde7c3a1b6b07421fade0b2e1722489b632a6072220d37ba8baeedfa04eb502a93d678c1ef2a543f091bced80fb27fc9f0e20808304b9120fe77d9826f204f5dbef3da251b1c4acbe8cd01565b7707ec7b32f2a0593d4f9aa1fe9f908ce7aa97583c50fa8a8b001a4fce5a10b179dc98bbf0c7b369e5058c847d60a466fb89a50947afa4240c7b93f49906ce476775499be5df7dbe4dd39000fadeef3a87c58c0a3aa5e0009e8959020d8f3b28d8db0a7a4911d348b6f85d46ceada50308413ec2f04b77ad24c5cb6bd0624c38c9fa34f946a23b48ad84fa7f4bf798c43d904a6d5749dd4cb2a753895860d7697b22cb53abb2b9391df2abd44895667a1f51ebfbf14eb7648f9fbd5b42677d5575edf3458bea0b477ced0a49237ce33f8db22f2d66a00e4eccf6ea49630f30185a6033bd6b3517b97e0d928c601fe01a597aa22d5e40991c6c205df654d34d912666bb8fb49f6566f5eed9d4990ec5e98fdc51da2606ffdf5b1eb73b29d32e23b47ab53bc7c82f
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168023);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/22");

  script_cve_id("CVE-2021-1622");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw49029");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cbr8-cops-Vc2ZsJSx");
  script_xref(name:"IAVA", value:"2021-A-0441");

  script_name(english:"Cisco IOS XE Software for cBR 8 Converged Broadband Routers Common Open Policy Service Denial of Service (cisco-sa-cbr8-cops-Vc2ZsJSx)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software for Cisco cBR-8 Converged Broadband Routers is affected
by a DoS vulnerability in the Common Open Policy Service (COPS). A deadlock condition exists in the COPS packet
processing that could allow allow an unauthenticated, remote attacker to cause resource exhaustion, resulting in a
denial of service (DoS) condition.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cbr8-cops-Vc2ZsJSx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3f46ab9");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw49029");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw49029");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1622");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(833);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var vuln_versions = make_list(
  '3.15.0S',
  '3.15.1S',
  '3.15.1xbS',
  '3.15.2S',
  '3.15.2xbS',
  '3.15.3S',
  '3.16.0S',
  '3.16.1S',
  '3.16.2S',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.18.0S',
  '3.18.0SP',
  '3.18.0aS',
  '3.18.1S',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.2aSP',
  '3.18.3SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.18.4SP',
  '3.18.5SP',
  '3.18.6SP',
  '16.4.1',
  '16.5.1',
  '16.6.1',
  '16.6.2',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1d',
  '16.8.1e',
  '16.9.1',
  '16.9.1a',
  '16.10.1',
  '16.10.1c',
  '16.10.1d',
  '16.10.1f',
  '16.10.1g',
  '16.12.1',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '17.2.1',
  '17.3.1',
  '17.3.1w',
  '17.3.2'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['cops_enabled'];

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvw49029',
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:vuln_versions
);
