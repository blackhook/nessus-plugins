#TRUSTED 67bb7738222cffcc5260ccb77c7bb4d5ded6329fcae733ddcb97363c34a90439d1cb58c256b117c0299ea01aa26e9156481d3b22dff2d5f23d69f338ac0a0c5596a8dbbfe89abd48bcbed6b0528b87ff1cf01e4441c35130f690cfc92cf36f88cddebde24c5abe1acbd5860082d8165c6e82670a7b749ba137bc90a08ec857539875d4620a96936356496bbbc6fd939cdcf7c22947af622edc1ef0af471c2289dc95f3e2b62f3fd0540a1be6e030e54142d686f5cfee5beb86b66543e61ff65f8eebc9ac82c5deb63ef2b7b38a2be190beef127734e7c044e09e56ae6dddb0b42b0d0894d5e33c820a7bd6eca03ee533955661f9e834f370981f792cb2488e2db5b1f7643037b42a2e1c4d754390edd3f0ea049b18d57459cbe3bdc203efeaecd2978e30b82256f24b434a180bc4548df3ca12468ee6f6cab4a48c8672d567aed61a2939e30cd0c2ee07b1db825cdf7ef7a40b342e4426f15765478cab0165309662a2af05fcb1980db5cf635041306ead0bfaf9382f158e171cb98fc17f2270c6145e20e8a866cc5fcf6cea87e4a77683d9f36aa7830391486d3350aa150067339776aae0722770cebd6924eb6e27c0096ac7fc3c22e916a1d9970c1a883bb31b1c6d06eab0b2b75cc936fbd6c12efebab3a58ea3971337e4a50cc7ef11d6f31bbc45ef2bc5486763bf64d7cd2509ade2b42ee11fa9604ca501d1cc9d6cd001
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127044);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-1904");
  script_bugtraq_id(108737);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy98103");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190612-iosxe-csrf");
  script_xref(name:"IAVA", value:"2019-A-0264");

  script_name(english:"Cisco IOS XE Software Web UI Cross-Site Request Forgery Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a cross-site request forgery (CSRF),
which exists in the web UI of the affected device. A remote attacker can exploit this to perform arbitrary actions
with the privilege level of the affected user.
Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190612-iosxe-csrf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?616fabb5");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy98103
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f9ff48b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCuy98103");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1904");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.5.9SQ',
  '3.2.11aSG',
  '3.2.0JA',
  '3.18.7SP',
  '3.18.6SP',
  '3.18.5SP',
  '3.18.4SP',
  '3.18.4S',
  '3.18.3bSP',
  '3.18.3aSP',
  '3.18.3SP',
  '3.18.3S',
  '3.18.2aSP',
  '3.18.2SP',
  '3.18.2S',
  '3.18.1iSP',
  '3.18.1hSP',
  '3.18.1gSP',
  '3.18.1cSP',
  '3.18.1bSP',
  '3.18.1aSP',
  '3.18.1SP',
  '3.18.1S',
  '3.18.0aS',
  '3.18.0SP',
  '3.18.0S',
  '3.17.4S',
  '3.17.3S',
  '3.17.2S ',
  '3.17.1aS',
  '3.17.1S',
  '3.17.0S',
  '3.16.9S',
  '3.16.8S',
  '3.16.7bS',
  '3.16.7aS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.6S',
  '3.16.5bS',
  '3.16.5aS',
  '3.16.5S',
  '3.16.4gS',
  '3.16.4eS',
  '3.16.4dS',
  '3.16.4cS',
  '3.16.4bS',
  '3.16.4aS',
  '3.16.4S',
  '3.16.3aS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.2aS',
  '3.16.2S',
  '3.16.1aS',
  '3.16.1S',
  '3.16.10S',
  '3.16.0cS',
  '3.16.0bS',
  '3.16.0aS',
  '3.16.0S',
  '3.15.4S',
  '3.15.3S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.1S',
  '3.15.0S',
  '3.11.0sE',
  '16.9.3h',
  '16.9.2h',
  '16.3.8',
  '16.3.7',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1',
  '16.1.3',
  '16.1.2',
  '16.1.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCuy98103'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
