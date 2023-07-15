#TRUSTED 63419b65e1905af6c2a22b6a56670a127131fb3cc91ea63300f08c79aab3fbc67016cc59e420ebb64a9a7b83f7960fd0a297e008c7ab69b27f765d15f8ffbe08e97fe2d299765580e48cbe704af0e764d4fede0dbefb01dc5be3e2d0b65ead54527c14bb0e167749e72d0be0820aa9165f904a36def3b27d2341d80d094d1da80ebc6025cb99162977b1ce795eda3db36ffa3fcc234db4dc37d5545ca9445867a5f8b43b1e2bba8be200a18a417ab63ec29d7f65bd456c621e3e2ec4e60e29c2445a5b6aeb8a054d81f355d6937cf3e829dac87d83aeca8dd9c3d6ffcdcdba947ff3158b59a8781c2396e57ba28d3905f54066cceb6598eaeeb6c9e7698024d1b03e86246b0cfa482169c8f12395ed6508be6a0983aaa49cf981578795609008c989eaff62cff61aed1cf40b9d82df8bb943b217f2caadd06c7697791a904feff45d25dffd75494c3a5f2956f3c8858f3866ae202245116396f1c66d2ed9377732ed7300e87be2bfadc46a8f13dd899bc42437c4566db4e91f1ef039088d2ea34df638848fc3261d599188fac6b7b001641d260e2dafcd451cecd7fba3c83011acb1022465cbdf6d486a91c5dba7802debb3ff1b3c47e98333b49a8f18a70b2e865b860fde7ae31e611a924b5382987c3b2f3b45f389231c5440627089cd72c415d77eabbd2def891492a6f5dc849ca71fbdb14135df574159f303fb7e11454b
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141371);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3416", "CVE-2020-3513");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr69196");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs62410");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-rsp3-rce-jVHg8Z7c");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software for ASR 900 Series Route Switch Processor 3 Arbitrary Code Execution (cisco-sa-iosxe-rsp3-rce-jVHg8Z7c)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XE for Cisco ASR 900 Series Aggregation Services Routers is affected by
multiple vulnerabilities due to incorrect validations by boot scripts when specific ROM monitor (ROMMON) variables
are set.  

An authenticated, local attacker with high privileges to execute persistent code at bootup could exploit this by
copying a specific file to the local file system of an affected device and defining specific ROMMON variables. A
successful exploit could allow the attacker to run arbitrary code on the underlying operating system (OS) with root
privileges. To exploit these vulnerabilities, an attacker would need to have access to the root shell on the device
or have physical access to the device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-rsp3-rce-jVHg8Z7c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7666b559");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr69196");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs62410");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr69196, CSCvs62410");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3416");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(749);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/12");

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

model = toupper(product_info['model']);
if (model !~ 'ASR90[0-9]([^0-9]|$)')
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_versions = make_list(
  '16.10.1',
  '16.11.1',
  '16.11.1a',
  '16.11.2',
  '16.12.1',
  '16.12.2',
  '16.12.2a',
  '16.12.3',
  '16.12.3s',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.10',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.5',
  '16.6.5a',
  '16.6.6',
  '16.6.7',
  '16.6.8',
  '16.7.1',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1b',
  '16.8.1c',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.2',
  '16.9.3',
  '16.9.3h',
  '16.9.4',
  '16.9.5',
  '16.9.5f',
  '17.1.1',
  '17.1.1a',
  '3.16.0S',
  '3.16.0aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.10S',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2aS',
  '3.16.2bS',
  '3.16.3S',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.6S',
  '3.16.6bS',
  '3.16.7S',
  '3.16.7aS',
  '3.16.7bS',
  '3.16.8S',
  '3.16.9S',
  '3.17.0S',
  '3.17.1S',
  '3.17.1aS',
  '3.17.2S',
  '3.17.3S',
  '3.17.4S',
  '3.18.0S',
  '3.18.0SP',
  '3.18.0aS',
  '3.18.1S',
  '3.18.1SP',
  '3.18.1bSP',
  '3.18.1gSP',
  '3.18.1hSP',
  '3.18.1iSP',
  '3.18.2S',
  '3.18.2SP',
  '3.18.3S',
  '3.18.3SP',
  '3.18.4S',
  '3.18.4SP',
  '3.18.5SP',
  '3.18.6SP',
  '3.18.7SP',
  '3.18.8SP',
  '3.18.8aSP'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr69196, CSCvs62410',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:vuln_versions
);
