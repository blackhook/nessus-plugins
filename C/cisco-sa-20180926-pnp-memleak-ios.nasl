#TRUSTED 5dbf135447795dfc7818eee0dc0fbc20508eef071ceadac90006fb458a98fcad3fee7932e11e8b0767a18ecd06d1bbbb04589aec14c1dbcec403a2f76d49bfff320b4f02721fc904097c1168e5ebd45a89e22a31635625831b897e6f3c08c0c65e7d64269ae824db31063f31df18f60e5478eff12997f578493f40874bb89660c3fc8d09668f4cd482c9a9d379c81ade9e8cdefc5e6d82678a4ce8fb2d4fb0839b7fb171ebe73fb5632ea4bf3c36ca76e35563117ce64d0063926e239df3dbe2e91bb8693ce09b8461f698b914b308eac10d1cc1b4dc0316e5762eb8e64daa5a350b2c513ee785c883662e6114f1a6820d94d0360403e7f7c6197487b430fa838bef25a831c96ad1f477362ad160fd274b1ea44d462c2ed162db5bca1049894feae8a83419bcd99001d497fe1d77967f95013e53f05e96d248dccbfea4f85d9d63ea4c115e1898246cea12d8fb5102a7f96083910b3e124e0ae38a6aa4ee6fed4c5eeaf5d723589bd35a2a7a050cbb5177e50f154faaca9951d4f63c044e1be9e6604879e48057a570b79e48396330ef3ad366a8d54c47dbc27f154dca01107178d35ebf9ba3f215f53ef6c65342cc7951683142c4fe3fe3bfe1af04ad1bb19f8b79b22f1b308478a9cefb8451695e6d131c5c895d15d82f50e5ea04d496c6e213ae45bea1f25605dc0a4d8d7b96b76e2d82647615386143c34251db76f2f92f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132048);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2018-15377");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi30136");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-pnp-memleak");

  script_name(english:"Cisco IOS Software Software Plug and Play Agent Memory Leak(cisco-sa-20180926-pnp-memleak)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by a memory leak vulnerability in the Cisco Network Plug
and Play agent due to insufficient input validation. An unauthenticated, remote attacker can exploit this, by sending
invalid data to the Cisco Network Plug and Play agent on an affected device, to cause a memory leak on an affected
device, causing it to reload.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-pnp-memleak
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f91b535a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi30136");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvi30136.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15377");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list = make_list(
  '15.2(4)E',
  '15.2(4)E1',
  '15.2(4)E2',
  '15.2(4m)E1',
  '15.2(5)E',
  '15.2(4)E3',
  '15.2(5a)E',
  '15.2(5)E1',
  '15.2(5b)E',
  '15.2(4m)E3',
  '15.2(5c)E',
  '15.2(4n)E2',
  '15.2(4o)E2',
  '15.2(5a)E1',
  '15.2(4)E4',
  '15.2(5)E2',
  '15.2(4p)E1',
  '15.2(6)E',
  '15.2(5)E2b',
  '15.2(4)E5',
  '15.2(5)E2c',
  '15.2(4m)E2',
  '15.2(4o)E3',
  '15.2(4q)E1',
  '15.2(6)E0a',
  '15.2(6)E1',
  '15.2(4)E5a',
  '15.2(6)E0c',
  '15.2(4)E6',
  '15.2(6)E1a',
  '15.2(6)E1s',
  '15.2(4s)E1',
  '15.2(4s)E2',
  '15.2(5)EX',
  '15.5(3)S',
  '15.5(3)S1',
  '15.5(3)S1a',
  '15.5(3)S2',
  '15.5(3)S0a',
  '15.5(3)S3',
  '15.5(3)S4',
  '15.5(3)S5',
  '15.5(3)S6',
  '15.5(3)S6a',
  '15.5(3)S7',
  '15.5(3)S6b',
  '15.2(4)EA',
  '15.2(4)EA1',
  '15.2(4)EA3',
  '15.2(5)EA',
  '15.2(4)EA4',
  '15.2(4)EA2',
  '15.2(4)EA5',
  '15.2(4)EA6',
  '15.5(3)M',
  '15.5(3)M1',
  '15.5(3)M0a',
  '15.5(3)M2',
  '15.5(3)M2a',
  '15.5(3)M3',
  '15.5(3)M4',
  '15.5(3)M4a',
  '15.5(3)M5',
  '15.5(3)M4b',
  '15.5(3)M4c',
  '15.5(3)M6',
  '15.5(3)M5a',
  '15.5(3)M7',
  '15.5(3)M6a',
  '15.5(3)SN0a',
  '15.5(3)SN',
  '15.6(1)S',
  '15.6(2)S',
  '15.6(2)S1',
  '15.6(1)S1',
  '15.6(1)S2',
  '15.6(2)S2',
  '15.6(1)S3',
  '15.6(2)S3',
  '15.6(1)S4',
  '15.6(2)S4',
  '15.6(1)T',
  '15.6(2)T',
  '15.6(1)T0a',
  '15.6(1)T1',
  '15.6(2)T1',
  '15.6(1)T2',
  '15.6(2)T0a',
  '15.6(2)T2',
  '15.6(1)T3',
  '15.6(2)T3',
  '15.3(3)JC6',
  '15.3(3)JC8',
  '15.3(3)JC9',
  '15.3(3)JC14',
  '15.3(1)SY',
  '15.3(0)SY',
  '15.3(1)SY1',
  '15.3(1)SY2',
  '15.6(2)SP',
  '15.6(2)SP1',
  '15.6(2)SP2',
  '15.6(2)SP3',
  '15.6(2)SP4',
  '15.6(2)SP3b',
  '15.6(1)SN',
  '15.6(1)SN1',
  '15.6(2)SN',
  '15.6(1)SN2',
  '15.6(1)SN3',
  '15.6(3)SN',
  '15.6(4)SN',
  '15.6(5)SN',
  '15.6(6)SN',
  '15.6(7)SN',
  '15.6(7)SN1',
  '15.3(3)JD3',
  '15.3(3)JD4',
  '15.3(3)JD5',
  '15.3(3)JD6',
  '15.3(3)JD7',
  '15.3(3)JD8',
  '15.3(3)JD9',
  '15.3(3)JD11',
  '15.3(3)JD12',
  '15.3(3)JD13',
  '15.3(3)JD14',
  '15.3(3)JD15',
  '15.6(3)M',
  '15.6(3)M1',
  '15.6(3)M0a',
  '15.6(3)M1a',
  '15.6(3)M1b',
  '15.6(3)M2',
  '15.6(3)M2a',
  '15.6(3)M3',
  '15.6(3)M3a',
  '15.6(3)M4',
  '15.2(4)EC1',
  '15.2(4)EC2',
  '15.4(1)SY',
  '15.4(1)SY1',
  '15.4(1)SY2',
  '15.4(1)SY3',
  '15.4(1)SY4',
  '15.3(3)JE',
  '15.3(3)JDA15',
  '15.5(1)SY',
  '15.5(1)SY1',
  '15.3(3)JF',
  '15.3(3)JF1',
  '15.3(3)JF2',
  '15.3(3)JF4',
  '15.3(3)JF5',
  '15.3(3)JF6',
  '15.3(3)JF7',
  '15.7(3)M',
  '15.7(3)M1',
  '15.7(3)M0a',
  '15.3(3)JG',
  '15.3(3)JG1',
  '15.3(3)JH',
  '15.3(3)JH1',
  '15.3(3)JI',
  '12.2(6)I1'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi30136'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
