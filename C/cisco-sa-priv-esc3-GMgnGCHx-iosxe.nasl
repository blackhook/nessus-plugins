#TRUSTED ac42a2654fbc616ef89f5a1d791e7252c281848fe715563edb40cad18ee3b199cceed7fb272d50304e17a263bb041fa2ead81cfa55dcb249567b3ac7b8ef2f8edac21ce1edf165cf5422b79376eb305e93e9adfe5ca8b9b73a6b2f43c97cacb18852fe158c84acf9870fa7114a284b880b9aa934a5dcb9603da73a6cb9ecbafdc8a9c724ae084e4ffc3053ec18dc3b522788d496e138de7cdec869070d68129538d7e3df97f20bc38f98fa855e12415552b445fe2aaa24d01105594bc1236ed9da8f959b2b590e17af5e0c704dfad6dfeb0ce876dacf4b2f0954870a1220ed317668a95f38414aee3ce551c443c135eb17d60f5ae98adbe5d8eba4f76bd51c6fe7c3d260ef6f75aa95ab2c2a0b3a70c489358e935057f644488b9e8b83a7716697341d489147d582f11085a3a29beb503378180858ca2c76cb3c217da4c89f19184aa9164ab76d42d92da271b54d3bb7f55da541a313ffb3aee2e858a7689710ac5a1f0b110b609bf39749bd928ba718dc703dd2af8d6834967eeff5436621f6cdbf20ad7763a1fd9ccdb2978958fd4c184a7d939b6797967235a28ea73e94993ff57ed92be89a753e2b3b9af64d25a76c382d2b67121dfe4a79eb93c8dda3b8fc840f2c515ca115c12c6c5c36a96765e44e55b93fb8eba2cd7ccc03b32753d80501d399567a3862a75af6df8b586b6242c50af6086cf24a27c0559528440996
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137332);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3213");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq26065");
  script_xref(name:"CISCO-SA", value:"cisco-sa-priv-esc3-GMgnGCHx");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Privilege Escalation (cisco-sa-priv-esc3-GMgnGCHx)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a privilege escalation vulnerability.
A vulnerability in the ROMMON of Cisco IOS XE Software could allow an authenticated, local attacker to elevate
privileges to those of the root user of the underlying operating system.

 Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-priv-esc3-GMgnGCHx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f6ce1dd");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq26065");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq26065");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3213");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/11");

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

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.9.2S',
  '3.9.1aS',
  '3.9.1S',
  '3.9.0aS',
  '3.9.0S',
  '3.8.2S',
  '3.8.1S',
  '3.8.0S',
  '3.18.8SP',
  '3.18.7SP',
  '3.18.6SP',
  '3.18.5SP',
  '3.18.4SP',
  '3.18.4S',
  '3.18.3SP',
  '3.18.3S',
  '3.18.2SP',
  '3.18.2S',
  '3.18.1iSP',
  '3.18.1hSP',
  '3.18.1gSP',
  '3.18.1cSP',
  '3.18.1bSP',
  '3.18.1SP',
  '3.18.1S',
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
  '3.11.4S',
  '3.11.3S',
  '3.11.2S',
  '3.11.1S',
  '3.11.0S',
  '3.10.9S',
  '3.10.8aS',
  '3.10.8S',
  '3.10.7S',
  '3.10.6S',
  '3.10.5S',
  '3.10.4S',
  '3.10.3S',
  '3.10.2tS',
  '3.10.2aS',
  '3.10.2S',
  '3.10.1S',
  '3.10.10S',
  '3.10.0S',
  '16.9.4c',
  '16.9.4',
  '16.9.3s',
  '16.9.3h',
  '16.9.3a',
  '16.9.3',
  '16.9.2s',
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
  '16.8.2',
  '16.8.1s',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.3',
  '16.7.2',
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
  '16.12.1t',
  '16.12.1s',
  '16.12.1c',
  '16.12.1a',
  '16.12.1',
  '16.11.2',
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1',
  '16.10.2',
  '16.10.1s',
  '16.10.1e',
  '16.10.1b',
  '16.10.1a',
  '16.10.1',
  '16.1.3',
  '16.1.2',
  '16.1.1'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq26065',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
