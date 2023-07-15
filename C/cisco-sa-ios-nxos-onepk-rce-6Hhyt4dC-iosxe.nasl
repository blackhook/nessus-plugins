#TRUSTED 4ee0a3a39128d12eb2def42016eeb6fad246045c2b101399a4fb1897ecf4ffcb5c514ec24f0741a0483b1786e20a8197b4ae347c008adc427407daf649e0b53b0c37ada37d664f12d6bb8aded7f46e89e46639dc0d97b0abc5bd484874b46822a1cc3c5301439ea702796ffe1de1fef9396cf29f354c673fa0814040c297eaa6a3edbb6ca15f7418c19ab8e57e03001c3a41171002e520748f1d1b02e01503ad746956f74183f3504b42a2dbad1e9d19c9803519c7a915a43512c1b83a3e538f52e2d24aae9f9a82e2c8cee5eefe470af379316d2bcf026999c24612ac029950fa4ee1fa779ee8f80cf874be62c7a23419384f96d7c46cd2b2a549a7ada6065567914d3c9d9703fb62ed3ee0ce993b35cedf0577ccc0ae418bc9b80c7f5db7400230e151186d9b52ff0fe62b31135995180afdf5187da0fc7621337df019246618fff1e5163cec7af8b67db7d177c4191a237863f0aaf72e729a7892fd22d6fc05f1430680c0ed1b4f7d18f5d668a5921d76ff394f5bfb90a4a3078853cddd5428fdbfed099c9e0f00e9ff0d90dc08cd63b141cee4f4e46d3d766173df6762268f0c3aa2b436d3b7d9d25a7b0f17d57d6e7e6c46324deb2d425aeb77beabfc4a498a66c728a310828760f0e85eb1f63083d770bae256838847ec0a14fe4cd510a877ecdfd5eacc3a7f9fd1a1a26b583b0f2f84ef567bce68e1a1bb08f9b49c94
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137902);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id("CVE-2020-3217");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh10810");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr80243");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs42159");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs42176");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs81070");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-nxos-onepk-rce-6Hhyt4dC");
  script_xref(name:"IAVA", value:"2020-A-0260");

  script_name(english:"IOS XE Software One Platform Kit Remote Code Execution Vulnerability (cisco-sa-ios-nxos-onepk-rce-6Hhyt4dC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-ios-nxos-onepk-rce-6Hhyt4dC)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE is affected by a remote code execution vulnerability.
Therefore there exists in Cisco One Platform Kit due to a vulnerability in the Topology Discovery Service.
An unauthenticated, adjacent attacker can exploit this to bypass authentication and execute arbitrary 
commands with root privileges. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-nxos-onepk-rce-6Hhyt4dC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38e0a857");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh10810");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr80243");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs42159");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs42176");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs81070");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvh10810, CSCvr80243, CSCvs42159, CSCvs42176,
CSCvs81070");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3217");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

get_kb_item_or_exit("Host/local_checks_enabled");

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.9.2bE',
  '3.9.2E',
  '3.9.1E',
  '3.9.0E',
  '3.8.9E',
  '3.8.8E',
  '3.8.7E',
  '3.8.6E',
  '3.8.5aE',
  '3.8.5E',
  '3.8.4E',
  '3.8.3E',
  '3.8.2E',
  '3.8.1E',
  '3.8.0E',
  '3.7.5E',
  '3.7.4E',
  '3.7.3E',
  '3.7.2E',
  '3.7.1E',
  '3.7.0E',
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
  '3.14.4S',
  '3.14.3S',
  '3.14.2S',
  '3.14.1S',
  '3.14.0S',
  '3.13.9S',
  '3.13.8S',
  '3.13.7aS',
  '3.13.7S',
  '3.13.6bS',
  '3.13.6aS',
  '3.13.6S',
  '3.13.5aS',
  '3.13.5S',
  '3.13.4S',
  '3.13.3S',
  '3.13.2aS',
  '3.13.2S',
  '3.13.1S',
  '3.13.10S',
  '3.13.0aS',
  '3.13.0S',
  '3.12.4S',
  '3.12.3S',
  '3.12.2S',
  '3.12.1S',
  '3.12.0aS',
  '3.12.0S',
  '3.11.0E',
  '3.10.3E',
  '3.10.2E',
  '3.10.1sE',
  '3.10.1aE',
  '3.10.1E',
  '3.10.0cE',
  '3.10.0E',
  '16.7.4',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.7a',
  '16.6.7',
  '16.6.6',
  '16.6.5b',
  '16.6.5a',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.9',
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
  '16.12.1y',
  '16.1.3',
  '16.1.2',
  '16.1.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['onep_status'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvh10810, CSCvr80243, CSCvs42159, CSCvs42176, CSCvs81070'
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
