#TRUSTED 515ec24205c8b680e1014273e42835eb82683af9d27ddbd2e73693664b7ee3efbdc73cee2b0c625a0bcef03507094c6cbdbabeb56e5ccd5ba53c2bf8afac4ffcf73fbe717c7f3538ff255cc86d23c51a66f9bbf8b2b9f62e23311231669d15a58da8bf713643d7570b524bbfcaee7ccb5e62d55a2b46c29502ded4c51999d5ee2357bed66ce4bddee422066784c4fa83702398e0e8d9182c317c77df0054e79296cf50be0e20005e977de44daa80e2660c3f9b803ef945d6a933baf2d3442ee0153f6cb5603721dec3853871945a78a716f9ba1c313e7d47e426e281768e9862ccfa854cb15a036e86d56b974dcf21c166bf7e0a2ebad477af3eb628b17de231b20a999e9e02b5ab357b3d29d1b81dfafc7f529197a64a182e379380a1f3390e5f4f86e02500d67f952381f3fc326dc03e1b383012f1fedfeaae6b6d8c0f59df85c076686ef5e239418a87faa1d7fae1de83058df59f55e7ac6429c306f2ce9d67d83181a592b11938e6a1c2803b3cf7b1593409a05845423f7f2d632f745661df4b99497db012974f1751348e0c98296e298febf699fbe4428eecbf718c4d29523b749ceb356a57920dd8d7f70df6cbc68dfaebe16f4afbaa2242ae108491a7a2a08e1c513241dd9e1ad97f00c24aa0c82150a5eeff891aed1d5ad719be049e94b4b3b27576627836f61f91b162dbfd73da5da472b8b53a5146b121442c660b
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130021);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2019-12647");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm01689");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190417-ios-xr-dos");
  script_xref(name:"IAVA", value:"2019-A-0354-S");

  script_name(english:"Cisco IOS XR gRPC Software Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS Software is
affected by a denial of service (DoS) vulnerability exists in Ident protocol
handler of Cisco IOS and IOS XE Software due to incorrectly handling memory 
structures, leading to a NULL pointer dereference. An unauthenticated,
remote attacker can exploit this issue, via opening a TCP connection to
specific ports and sending traffic over that connection, to cause the
affected device to reload, resulting in a denial of service (DoS)
condition. 

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-identd-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09b027b1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm01689");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvm01689");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12647");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(476);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list = make_list(
 	'12.1(12)',
	'12.1(1c)',
	'12.1(14)',
	'12.1(2a)',
	'12.1(7)',
	'12.1(9)',
	'12.1(4a)',
	'12.1(3b)',
	'12.1(11a)',
	'12.1(5b)',
	'12.1(6)',
	'12.1(4b)',
	'12.1(12a)',
	'12.1(11b)',
	'12.1(5)',
	'12.1(16)',
	'12.1(12c)',
	'12.1(8b)',
	'12.1(13)',
	'12.1(7a)',
	'12.1(12d)',
	'12.1(7b)',
	'12.1(13a)',
	'12.1(22a)',
	'12.1(24)',
	'12.1(17)',
	'12.1(5e)',
	'12.1(8)',
	'12.1(18)',
	'12.1(1a)',
	'12.1(1)',
	'12.1(5c)',
	'12.1(6b)',
	'12.1(5a)',
	'12.1(27a)',
	'12.1(8a)',
	'12.1(8c)',
	'12.1(20)',
	'12.1(2b)',
	'12.1(17a)',
	'12.1(19)',
	'12.1(27)',
	'12.1(2)',
	'12.1(6a)',
	'12.1(22b)',
	'12.1(15)',
	'12.1(20a)',
	'12.1(26)',
	'12.1(10)',
	'12.1(4c)',
	'12.1(10a)',
	'12.1(21)',
	'12.1(22)',
	'12.1(11)',
	'12.1(12b)',
	'12.1(22c)',
	'12.1(27b)',
	'12.1(9a)',
	'12.1(3)',
	'12.1(25)',
	'12.1(7c)',
	'12.1(3a)',
	'12.1(4)',
	'12.1(3a)XI9',
	'12.1(3)XI',
	'12.1(3a)XI8',
	'12.1(3a)XI3',
	'12.1(3a)XI1',
	'12.1(3a)XI7',
	'12.1(3a)XI6',
	'12.1(3a)XI4',
	'12.1(3a)XI2',
	'12.1(3a)XI5',
	'12.0(11)S5',
	'12.0(2)S',
	'12.0(4)S',
	'12.0(11)S4',
	'12.0(28)S4a',
	'12.0(14)S4',
	'12.0(14)S6',
	'12.0(12)S1',
	'12.0(15)S2',
	'12.0(10)S3',
	'12.0(10)S3b',
	'12.0(3)S',
	'12.0(10)S2',
	'12.0(11)S1',
	'12.0(13)S4',
	'12.0(15)S5',
	'12.0(13)S3',
	'12.0(10)S5',
	'12.0(10)S6',
	'12.0(12)S2',
	'12.0(11)S2',
	'12.0(14)S5',
	'12.2(4)B',
	'12.2(8)B',
	'12.2(4)B7a',
	'12.2(4)B7',
	'12.2(4)B2',
	'12.2(4)B6',
	'12.2(4)B1',
	'12.2(8)B1',
	'12.2(4)B4',
	'12.2(4)B3',
	'12.2(4)B8',
	'12.2(8)B2',
	'12.2(4)B5',
	'12.2(14)S',
	'12.2(20)S',
	'12.2(18)S',
	'12.2(11)S',
	'12.2(14)S16',
	'12.2(25)S',
	'12.2(9)S',
	'12.2(20)S10',
	'12.2(20)S8',
	'12.2(20)S2a',
	'12.2(14)S7',
	'12.2(14)S11',
	'12.2(20)S4a',
	'12.2(25)S12',
	'12.2(25)S4',
	'12.2(14)S18',
	'12.2(20)S9a',
	'12.2(18)S8',
	'12.2(11)S2',
	'12.2(18)S10',
	'12.2(25)S15',
	'12.2(20)S5',
	'12.2(25)S7',
	'12.2(18)S7',
	'12.2(14)S9a',
	'12.2(25)S14',
	'12.2(14)S10',
	'12.2(25)S11',
	'12.2(14)S13',
	'12.2(18)S1',
	'12.2(14)S4',
	'12.2(20)S9b',
	'12.2(14)S13a',
	'12.2(18)S11',
	'12.2(18)S5',
	'12.2(20)S4',
	'12.2(25)S10',
	'12.2(20)S7',
	'12.2(18)S2',
	'12.2(25)S5',
	'12.2(14)S17',
	'12.2(18)S9',
	'12.2(11)S1',
	'12.2(14)S3',
	'12.2(18)S6',
	'12.2(18)S12',
	'12.2(25)S13',
	'12.2(18)S4',
	'12.2(25)S2',
	'12.2(20)S2',
	'12.2(20)S12',
	'12.2(14)S6',
	'12.2(14)S12',
	'12.2(14)S11b',
	'12.2(14)S9c',
	'12.2(20)S11',
	'12.2(25)S8',
	'12.2(20)S14',
	'12.2(20)S9',
	'12.2(14)S15',
	'12.2(14)S1',
	'12.2(14)S9',
	'12.2(14)S2',
	'12.2(14)S19',
	'12.2(14)S8',
	'12.2(18)S3',
	'12.2(20)S6',
	'12.2(11)S3',
	'12.2(14)S13b',
	'12.2(14)S5',
	'12.2(20)S3',
	'12.2(25)S1',
	'12.2(18)S13',
	'12.2(25)S9',
	'12.2(14)S14',
	'12.2(25)S3',
	'12.2(20)S1',
	'12.2(20)S13',
	'12.2(25)S6',
	'12.2(14)S11a',
	'12.2(14)S9b',
	'12.2(20)S6a',
	'12.2(2)XA',
	'12.2(2)XA2',
	'12.2(2)XA3',
	'12.2(2)XA4',
	'12.2(2)XA5',
	'12.2(2)XA1',
	'12.2(2)XB11',
	'12.2(2)XB5',
	'12.2(2)XB2',
	'12.2(2)XB10',
	'12.2(2)XB7',
	'12.2(2)XB4',
	'12.2(2)XB3',
	'12.2(2)XB6',
	'12.2(2)XB14',
	'12.2(2)XB12',
	'12.2(2)XB9',
	'12.2(2)XB15',
	'12.2(2)XB8',
	'12.2(2)XB16',
	'12.2(2)XG',
	'12.2(4)XL',
	'12.2(4)XL2',
	'12.2(4)XL4',
	'12.2(4)XL3',
	'12.2(10a)',
	'12.2(1)',
	'12.2(21b)',
	'12.2(10)',
	'12.2(1a)',
	'12.2(1b)',
	'12.2(1c)',
	'12.2(1d)',
	'12.2(10b)',
	'12.2(10d)',
	'12.2(10g)',
	'12.2(3b)',
	'12.2(3c)',
	'12.2(3d)',
	'12.2(3e)',
	'12.2(3g)',
	'12.2(3)',
	'12.2(5)',
	'12.2(5a)',
	'12.2(5b)',
	'12.2(5c)',
	'12.2(5d)',
	'12.2(6g)',
	'12.2(6h)',
	'12.2(6i)',
	'12.2(6j)',
	'12.2(6)',
	'12.2(6a)',
	'12.2(6b)',
	'12.2(6c)',
	'12.2(6d)',
	'12.2(6e)',
	'12.2(6f)',
	'12.2(7a)',
	'12.2(7b)',
	'12.2(7c)',
	'12.2(7g)',
	'12.2(7)',
	'12.2(37)',
	'12.2(19b)',
	'12.2(24b)',
	'12.2(12e)',
	'12.2(28)',
	'12.2(34)',
	'12.2(34a)',
	'12.2(46a)',
	'12.2(12b)',
	'12.2(26b)',
	'12.2(28a)',
	'12.2(12i)',
	'12.2(19)',
	'12.2(24)',
	'12.2(12g)',
	'12.2(13c)',
	'12.2(12f)',
	'12.2(12c)',
	'12.2(32)',
	'12.2(31)',
	'12.2(26a)',
	'12.2(27)',
	'12.2(12d)',
	'12.2(17e)',
	'12.2(28d)',
	'12.2(17a)',
	'12.2(12k)',
	'12.2(13e)',
	'12.2(12a)',
	'12.2(19c)',
	'12.2(27b)',
	'12.2(17b)',
	'12.2(23)',
	'12.2(27a)',
	'12.2(16)',
	'12.2(12m)',
	'12.2(40)',
	'12.2(28c)',
	'12.2(24a)',
	'12.2(21a)',
	'12.2(13b)',
	'12.2(23a)',
	'12.2(17d)',
	'12.2(26)',
	'12.2(23c)',
	'12.2(16b)',
	'12.2(13)',
	'12.2(19a)',
	'12.2(17f)',
	'12.2(28b)',
	'12.2(23d)',
	'12.2(12)',
	'12.2(12j)',
	'12.2(23f)',
	'12.2(17)',
	'12.2(16c)',
	'12.2(16a)',
	'12.2(27c)',
	'12.2(12l)',
	'12.2(12h)',
	'12.2(16f)',
	'12.2(29a)',
	'12.2(29b)',
	'12.2(13a)',
	'12.2(40a)',
	'12.2(26c)',
	'12.2(23e)',
	'12.2(21)',
	'12.2(46)',
	'12.2(29)',
	'12.2(2)XN',
	'12.2(31)XN',
	'12.2(31)XN2',
	'12.2(31b)XN3',
	'12.2(31)XN3',
	'12.2(31a)XN3',
	'12.2(31c)XN2',
	'12.2(31a)XN2',
	'12.2(31b)XN2',
	'12.2(31)XN1',
	'12.2(31c)XN3',
	'12.2(8)YD',
	'12.2(8)YD3',
	'12.2(8)YD2',
	'12.2(8)YD1',
	'12.0(19)',
	'12.0(2a)',
	'12.0(6)',
	'12.0(13)',
	'12.0(1)',
	'12.0(9)',
	'12.0(16)',
	'12.0(2)',
	'12.0(28c)',
	'12.0(18a)',
	'12.0(17)',
	'12.0(19a)',
	'12.0(3a)',
	'12.0(8a)',
	'12.0(16a)',
	'12.0(18)',
	'12.0(6b)',
	'12.0(13a)',
	'12.0(20)',
	'12.0(28b)',
	'12.0(7)',
	'12.0(25)',
	'12.0(15b)',
	'12.0(28d)',
	'12.0(26)',
	'12.0(3)',
	'12.0(15)',
	'12.0(11a)',
	'12.0(4)',
	'12.0(15a)',
	'12.0(4b)',
	'12.0(8)',
	'12.0(8b)',
	'12.0(21a)',
	'12.0(22)',
	'12.0(19b)',
	'12.0(18b)',
	'12.0(17a)',
	'12.0(1a)',
	'12.0(4a)',
	'12.0(10)',
	'12.0(24)',
	'12.0(12)',
	'12.0(11)',
	'12.0(23)',
	'12.0(14)',
	'12.0(5a)',
	'12.0(20a)',
	'12.0(14a)',
	'12.0(2b)',
	'12.0(12a)',
	'12.0(6a)',
	'12.0(7a)',
	'12.0(3d)',
	'12.0(28a)',
	'12.0(9a)',
	'12.0(3b)',
	'12.0(28)',
	'12.0(10a)',
	'12.0(16b)',
	'12.0(21)',
	'12.0(5)',
	'12.0(27)',
	'12.0(3c)',
	'12.0(5)XE5',
	'12.0(3)XE1',
	'12.0(5)XE',
	'12.0(2)XE4',
	'12.0(5)XE8',
	'12.0(2)XE3',
	'12.0(5)XE7',
	'12.0(4)XE2',
	'12.0(7)XE',
	'12.0(2)XE1',
	'12.0(3)XE2',
	'12.0(5)XE4',
	'12.0(5)XE2',
	'12.0(5)XE1',
	'12.0(7)XE2',
	'12.0(4)XE',
	'12.0(5)XE6',
	'12.0(2)XE',
	'12.0(7)XE1',
	'12.0(2)XE2',
	'12.0(1)XE',
	'12.0(5)XE3',
	'12.0(7)XK2',
	'12.0(5)XK1',
	'12.0(7)XK1',
	'12.0(5)XK2',
	'12.0(7)XK3',
	'12.0(5)XK',
	'12.0(7)XK',
	'12.1(5a)E',
	'12.1(13)E14',
	'12.1(8b)E18',
	'12.1(8b)E14',
	'12.1(8b)E15',
	'12.1(22)E2',
	'12.1(8b)E16',
	'12.1(8b)E12',
	'12.1(26)E',
	'12.1(23)E',
	'12.1(8b)E11',
	'12.1(12c)E1',
	'12.1(13)E',
	'12.1(13)E9',
	'12.1(13)E7',
	'12.1(13)E13',
	'12.1(13)E11',
	'12.1(20)E3',
	'12.1(20)E',
	'12.1(1)E',
	'12.1(10)E',
	'12.1(11b)E',
	'12.1(12c)E',
	'12.1(14)E',
	'12.1(19)E',
	'12.1(2)E',
	'12.1(22)E',
	'12.1(3a)E',
	'12.1(4)E',
	'12.1(6)E',
	'12.1(7)E',
	'12.1(8a)E',
	'12.1(9)E',
	'12.1(27b)E',
	'12.1(26)E7',
	'12.1(27b)E1',
	'12.1(5a)E6',
	'12.1(10)E5',
	'12.1(23)E4',
	'12.1(26)E8',
	'12.1(19)E6',
	'12.1(19)E1a',
	'12.1(8a)E3',
	'12.1(14)E4',
	'12.1(5b)E7',
	'12.1(9)E2',
	'12.1(11b)E12',
	'12.1(3a)E7',
	'12.1(6)E5',
	'12.1(12c)E7',
	'12.1(10)E6',
	'12.1(14)E3',
	'12.1(11b)E4',
	'12.1(13)E4',
	'12.1(7)E0a',
	'12.1(5a)E1',
	'12.1(5c)E11',
	'12.1(26)E3',
	'12.1(20)E5',
	'12.1(5c)E9',
	'12.1(13)E16',
	'12.1(8b)E20',
	'12.1(22)E5',
	'12.1(20)E4',
	'12.1(27b)E3',
	'12.1(7a)E5',
	'12.1(8b)E6',
	'12.1(22)E6',
	'12.1(6)E6',
	'12.1(9)E3',
	'12.1(14)E6',
	'12.1(6)E3',
	'12.1(10)E7',
	'12.1(3a)E4',
	'12.1(8b)E7',
	'12.1(6)E13',
	'12.1(8b)E8',
	'12.1(3a)E1',
	'12.1(7a)E1a',
	'12.1(13)E3',
	'12.1(6)E8',
	'12.1(19)E3',
	'12.1(13)E15',
	'12.1(13)E6',
	'12.1(26)E5',
	'12.1(4)E3',
	'12.1(1)E6',
	'12.1(8b)E10',
	'12.1(2)E2',
	'12.1(12c)E4',
	'12.1(20)E2',
	'12.1(5a)E2',
	'12.1(6)E2',
	'12.1(22)E3',
	'12.1(1)E1',
	'12.1(7a)E3',
	'12.1(27b)E4',
	'12.1(11b)E8',
	'12.1(20)E1',
	'12.1(22)E4',
	'12.1(6)E9',
	'12.1(7a)E4',
	'12.1(8b)E9',
	'12.1(1)E5',
	'12.1(5c)E12',
	'12.1(26)E2',
	'12.1(11b)E9',
	'12.1(22)E1',
	'12.1(5c)E8',
	'12.1(13)E17',
	'12.1(6)E12',
	'12.1(10)E1',
	'12.1(7a)E6',
	'12.1(1)E4',
	'12.1(10)E6a',
	'12.1(23)E2',
	'12.1(13)E1',
	'12.1(4)E1',
	'12.1(3a)E6',
	'12.1(12c)E6',
	'12.1(26)E4',
	'12.1(19)E2',
	'12.1(11b)E3',
	'12.1(14)E10',
	'12.1(13)E10',
	'12.1(23)E1',
	'12.1(11b)E14',
	'12.1(2)E1',
	'12.1(10)E2',
	'12.1(8a)E1',
	'12.1(19)E7',
	'12.1(26)E9',
	'12.1(8a)E4',
	'12.1(14)E5',
	'12.1(11b)E2',
	'12.1(6)E1',
	'12.1(11b)E6',
	'12.1(1)E2',
	'12.1(27b)E2',
	'12.1(14)E8',
	'12.1(10)E3',
	'12.1(8b)E13',
	'12.1(7a)E2',
	'12.1(8a)E5',
	'12.1(19)E1',
	'12.1(14)E2',
	'12.1(12c)E2',
	'12.1(11b)E1',
	'12.1(11b)E7',
	'12.1(11b)E10',
	'12.1(1)E3',
	'12.1(12c)E5',
	'12.1(11b)E0a',
	'12.1(10)E8',
	'12.1(14)E1',
	'12.1(3a)E8',
	'12.1(13)E2',
	'12.1(26)E1',
	'12.1(11b)E11',
	'12.1(6)E4',
	'12.1(5a)E4',
	'12.1(8a)E2',
	'12.1(19)E4',
	'12.1(5c)E10',
	'12.1(26)E6',
	'12.1(7a)E1',
	'12.1(13)E5',
	'12.1(13)E12',
	'12.1(3a)E3',
	'12.1(23)E3',
	'12.1(3a)E5',
	'12.1(5a)E5',
	'12.1(20)E6',
	'12.1(8b)E19',
	'12.1(14)E7',
	'12.1(9)E1',
	'12.1(13)E8',
	'12.1(10)E4',
	'12.1(5)XM4',
	'12.1(5)XM6',
	'12.1(5)XM8',
	'12.1(5)XM3',
	'12.1(5)XM2',
	'12.1(5)XM5',
	'12.1(5)XM1',
	'12.1(5)XM',
	'12.1(5)XM7',
	'12.1(5)YB2',
	'12.1(5)YB5',
	'12.1(5)YB',
	'12.1(5)YB4',
	'12.2(2)DD',
	'12.2(2)DD4',
	'12.2(2)DD3',
	'12.2(2)DD2',
	'12.2(2)DD1',
	'12.2(2)XK',
	'12.2(2)XK2',
	'12.0(1)T',
	'12.0(3)T1',
	'12.0(2a)T1',
	'12.0(7)T1',
	'12.0(2)T',
	'12.0(4)T',
	'12.0(3)T3',
	'12.0(7)T3',
	'12.0(1)T1',
	'12.0(7)T2',
	'12.0(7)T',
	'12.0(5)T',
	'12.0(3)T',
	'12.0(5)T1',
	'12.0(4)T1',
	'12.0(5)T2',
	'12.0(3)T2',
	'12.1(1)T',
	'12.1(5)T2',
	'12.1(5)T10',
	'12.1(5)T8a',
	'12.1(5)T9',
	'12.1(3)T',
	'12.1(2a)T1',
	'12.1(5)T17',
	'12.1(5)T15',
	'12.1(5)T20',
	'12.1(5)T4',
	'12.1(5)T3',
	'12.1(5)T14',
	'12.1(5)T8b',
	'12.1(3a)T1',
	'12.1(3a)T7',
	'12.1(3a)T2',
	'12.1(3a)T6',
	'12.1(5)T8c',
	'12.1(3a)T3',
	'12.1(5)T6',
	'12.1(2)T',
	'12.1(5)T12',
	'12.1(5)T7',
	'12.1(1a)T1',
	'12.1(5)T',
	'12.1(3a)T8',
	'12.1(5)T8',
	'12.1(5)T19',
	'12.1(5)T1',
	'12.1(5)T18',
	'12.1(2a)T2',
	'12.1(5)T5',
	'12.1(1)EX',
	'12.1(5c)EX',
	'12.1(8a)EX',
	'12.1(9)EX',
	'12.1(10)EX',
	'12.1(11b)EX',
	'12.1(12c)EX',
	'12.1(13)EX',
	'12.1(6)EX',
	'12.1(13)EX3',
	'12.1(9)EX1',
	'12.1(8b)EX3',
	'12.1(10)EX2',
	'12.1(5c)EX1',
	'12.1(1)EX1',
	'12.1(8b)EX5',
	'12.1(12c)EX1',
	'12.1(10)EX1',
	'12.1(8a)EX1',
	'12.1(8b)EX2',
	'12.1(13)EX1',
	'12.1(11b)EX1',
	'12.1(8b)EX4',
	'12.1(9)EX3',
	'12.1(9)EX2',
	'12.1(5c)EX3',
	'12.1(13)EX2',
	'12.1(20)EA1b',
	'12.1(9)EA1d',
	'12.1(8)EA1b',
	'12.1(6)EA2a',
	'12.1(6)EA2',
	'12.1(9)EA1a',
	'12.1(9)EA1c',
	'12.1(6)EA1a',
	'12.1(6)EA2b',
	'12.1(6)EA2c',
	'12.0(31)SZ2',
	'12.2(4)BW',
	'12.2(4)BW1a',
	'12.2(4)BW2',
	'12.2(4)BW1',
	'12.2(1)DX',
	'12.2(2)DX',
	'12.2(2)DX2',
	'12.2(1)DX1',
	'12.2(2)DX3',
	'12.2(2)DX1',
	'12.2(8)MC2',
	'12.2(8)MC2d',
	'12.2(8)MC2b',
	'12.2(8)MC2c',
	'12.2(8)MC1',
	'12.2(4)MX',
	'12.2(4)MX1',
	'12.2(4)MX2',
	'12.2(14)SZ',
	'12.2(14)SZ5',
	'12.2(14)SZ6',
	'12.2(14)SZ3',
	'12.2(14)SZ4',
	'12.2(14)SZ1',
	'12.2(14)SZ2',
	'12.2(2)XU',
	'12.2(2)XU2',
	'12.2(2)XU4',
	'12.2(2)XU3',
	'12.2(9)YO',
	'12.2(9)YO3',
	'12.2(9)YO2',
	'12.2(9)YO1',
	'12.2(9)YO4',
	'12.2(11)YX',
	'12.2(11)YX1',
	'12.2(8)YY',
	'12.2(8)YY4',
	'12.2(8)YY3',
	'12.2(8)YY2',
	'12.2(8)YY1',
	'12.2(11)YZ',
	'12.2(11)YZ1',
	'12.2(11)YZ3',
	'12.2(11)YZ2',
	'12.2(9)ZA',
	'12.2(14)ZA',
	'12.2(14)ZA3',
	'12.2(14)ZA2',
	'12.2(14)ZA5',
	'12.2(14)ZA4',
	'12.2(14)ZA6',
	'12.2(14)ZA7',
	'12.2(8)ZB',
	'12.0(5)XT1',
	'12.2(4)XZ',
	'12.2(4)XZ1',
	'12.2(4)XZ7',
	'12.2(4)XZ6',
	'12.2(4)XZ5',
	'12.2(4)XZ4',
	'12.2(4)XZ3',
	'12.2(4)XZ2',
	'12.3(7)XI3a',
	'12.2(14)SU',
	'12.2(14)SU1',
	'12.2(14)SU2',
	'12.2(17d)SXB',
	'12.2(17d)SXB6',
	'12.2(17d)SXB11',
	'12.2(17d)SXB7',
	'12.2(17d)SXB4',
	'12.2(17d)SXB2',
	'12.2(17d)SXB3',
	'12.2(17d)SXB5',
	'12.2(17d)SXB10',
	'12.2(17d)SXB8',
	'12.2(17d)SXB11a',
	'12.2(17d)SXB1',
	'12.2(17d)SXB9',
	'12.2(17b)SXA',
	'12.2(17b)SXA1',
	'12.2(17b)SXA2',
	'12.2(18)SXD',
	'12.2(18)SXD7a',
	'12.2(18)SXD7b',
	'12.2(18)SXD1',
	'12.2(18)SXD6',
	'12.2(18)SXD7',
	'12.2(18)SXD5',
	'12.2(18)SXD4',
	'12.2(18)SXD2',
	'12.2(18)SXD3',
	'12.2(33)ZI',
	'12.3(11)YF2',
	'12.2(1)M0',
	'12.2(6c)M1',
	'12.2(23c)M0',
	'12.2(12b)M1',
	'12.2(13b)M1',
	'12.2(12h)M1',
	'12.2(13b)M2',
	'12.2(4)BY',
	'12.2(4)BY1',
	'12.2(4)XV',
	'12.2(4)XV1',
	'12.2(4)XV2',
	'12.2(4)XV4',
	'12.2(4)XV4a',
	'12.2(4)XV3',
	'12.2(4)XV5',
	'12.3(2)JA3',
	'12.3(2)JA4',
	'12.3(11)JA2',
	'12.2(60)EZ16',
	'12.3(8)JK',
	'12.2(18)SXF',
	'12.2(18)SXF5',
	'12.2(18)SXF6',
	'12.2(18)SXF15',
	'12.2(18)SXF1',
	'12.2(18)SXF10',
	'12.2(18)SXF17b',
	'12.2(18)SXF4',
	'12.2(18)SXF15a',
	'12.2(18)SXF3',
	'12.2(18)SXF17',
	'12.2(18)SXF12',
	'12.2(18)SXF8',
	'12.2(18)SXF10a',
	'12.2(18)SXF16',
	'12.2(18)SXF7',
	'12.2(18)SXF17a',
	'12.2(18)SXF13a',
	'12.2(18)SXF14',
	'12.2(18)SXF12a',
	'12.2(18)SXF9',
	'12.2(18)SXF13b',
	'12.2(18)SXF13',
	'12.2(18)SXF2',
	'12.2(18)SXF11',
	'12.2(27)SBC',
	'12.2(27)SBC2',
	'12.2(27)SBC3',
	'12.2(27)SBC4',
	'12.2(27)SBC5',
	'12.2(27)SBC1',
	'12.2(18)SXE',
	'12.2(18)SXE2',
	'12.2(18)SXE6',
	'12.2(18)SXE3',
	'12.2(18)SXE6a',
	'12.2(18)SXE4',
	'12.2(18)SXE6b',
	'12.2(18)SXE1',
	'12.2(18)SXE5',
	'12.3(11)JX',
	'12.3(7)JX9',
	'12.3(11)JX1',
	'12.1(2)GB',
	'12.2(28)SB2',
	'12.2(28)SB',
	'12.2(28)SB10',
	'12.2(31)SB9b',
	'12.2(31)SB4',
	'12.2(31)SB3x',
	'12.2(33)SB3',
	'12.2(28)SB11',
	'12.2(31)SB5',
	'12.2(31)SB10',
	'12.2(33)SB9',
	'12.2(28)SB3',
	'12.2(31)SB15',
	'12.2(33)SB10',
	'12.2(33)SB6',
	'12.2(28)SB5',
	'12.2(31)SB11',
	'12.2(28)SB12',
	'12.2(31)SB7',
	'12.2(33)SB5',
	'12.2(31)SB6',
	'12.2(28)SB1',
	'12.2(33)SB8',
	'12.2(28)SB6',
	'12.2(31)SB4a',
	'12.2(31)SB17',
	'12.2(28)SB8',
	'12.2(31)SB13',
	'12.2(31)SB9',
	'12.2(28)SB4',
	'12.2(31)SB16',
	'12.2(31)SB12',
	'12.2(31)SB20',
	'12.2(33)SB8c',
	'12.2(31)SB8a',
	'12.2(28)SB7',
	'12.2(33)SB2',
	'12.2(28)SB9',
	'12.2(31)SB8',
	'12.2(31)SB3',
	'12.2(31)SB18',
	'12.2(31)SB2',
	'12.2(31)SB14',
	'12.2(31)SB19',
	'12.2(33)SB',
	'12.2(33)SB7',
	'12.2(33)SB1',
	'12.2(33)SB4',
	'12.2(28)SB13',
	'12.2(31)SB21',
	'12.2(33)SB8a',
	'12.2(33)SRA',
	'12.2(33)SRA6',
	'12.2(33)SRA7',
	'12.2(33)SRA2',
	'12.2(33)SRA3',
	'12.2(33)SRA1',
	'12.2(33)SRA4',
	'12.2(33)SRA5',
	'12.2(28)ZV',
	'12.2(28)ZV1',
	'12.2(33)ZW',
	'12.2(13)ZT',
	'12.2(18)IXA',
	'12.2(18)IXB',
	'12.2(18)IXB2',
	'12.2(18)IXB1',
	'12.2(18)IXC',
	'12.2(18)IXD',
	'12.2(18)IXD1',
	'12.2(18)ZU',
	'12.2(18)ZU1',
	'12.2(18)ZU2',
	'12.2(18)ZY',
	'12.2(18)ZY1',
	'12.2(18)ZY2',
	'12.4(11)MD2',
	'12.2(33)SRB',
	'12.2(33)SRB4',
	'12.2(33)SRB5a',
	'12.2(33)SRB3',
	'12.2(33)SRB1',
	'12.2(33)SRB7',
	'12.2(33)SRB6',
	'12.2(33)SRB5',
	'12.2(33)SRB2',
	'12.2(18)IXE',
	'12.2(27)SBA4',
	'12.2(33)SRC2',
	'12.2(33)SRC',
	'12.2(33)SRC3',
	'12.2(33)SRC5',
	'12.2(33)SRC6',
	'12.2(33)SRC4',
	'12.2(33)SRC1',
	'12.2(33)SXH3a',
	'12.2(33)SXH8a',
	'12.2(33)SXH3',
	'12.2(33)SXH4',
	'12.2(33)SXH7',
	'12.2(33)SXH',
	'12.2(33)SXH8',
	'12.2(33)SXH7v',
	'12.2(33)SXH2a',
	'12.2(33)SXH2',
	'12.2(33)SXH1',
	'12.2(33)SXH5',
	'12.2(33)SXH0a',
	'12.2(33)SXH7w',
	'12.2(33)SXH6',
	'12.2(33)SXH8b',
	'12.2(33)IRA',
	'12.2(33)IRB',
	'12.2(18)IXG',
	'12.2(18)IXF',
	'12.2(18)IXF1',
	'12.2(33)SCB9',
	'12.2(33)SCB',
	'12.2(33)SCB6',
	'12.2(33)SCB3',
	'12.2(33)SCB10',
	'12.2(33)SCB4',
	'12.2(33)SCB2',
	'12.2(33)SCB7',
	'12.2(33)SCB1',
	'12.2(33)SCB5',
	'12.2(33)SCB8',
	'12.2(33)SCB11',
	'12.2(33)SRD7',
	'12.2(33)SRD6',
	'12.2(33)SRD4a',
	'12.2(33)SRD2a',
	'12.2(33)SRD4',
	'12.2(33)SRD5',
	'12.2(33)SRD3',
	'12.2(33)SRD2',
	'12.2(33)SRD1',
	'12.2(33)SRD',
	'12.2(33)SRD8',
	'12.2(33)SXI2',
	'12.2(33)SXI3',
	'12.2(33)SXI5',
	'12.2(33)SXI4a',
	'12.2(33)SXI3a',
	'12.2(33)SXI4',
	'12.2(33)SXI2a',
	'12.2(33)SXI',
	'12.2(33)SXI3z',
	'12.2(33)SXI6',
	'12.2(33)SXI7',
	'12.2(33)SXI1',
	'12.2(33)SXI5a',
	'12.2(33)SXI8',
	'12.2(33)SXI9',
	'12.2(33)SXI8a',
	'12.2(33)SXI10',
	'12.2(33)SXI9a',
	'12.2(33)SXI11',
	'12.2(33)SXI12',
	'12.2(33)SXI13',
	'12.2(33)SXI14',
	'12.2(18)ZYA2',
	'12.2(18)ZYA',
	'12.2(18)ZYA3a',
	'12.2(18)ZYA1',
	'12.2(18)ZYA3',
	'12.2(18)ZYA3b',
	'12.2(18)ZYA3c',
	'12.4(23c)JY',
	'12.2(33)IRC',
	'12.2(18)IXH1',
	'12.2(18)IXH',
	'12.2(33)SCC',
	'12.2(33)SCC2',
	'12.2(33)SCC6',
	'12.2(33)SCC7',
	'12.2(33)SCC5',
	'12.2(33)SCC4',
	'12.2(33)SCC3',
	'12.2(33)SCC1',
	'12.2(33)SCD5',
	'12.2(33)SCD1',
	'12.2(33)SCD7',
	'12.2(33)SCD4',
	'12.2(33)SCD',
	'12.2(33)SCD6',
	'12.2(33)SCD3',
	'12.2(33)SCD2',
	'12.2(33)SCD8',
	'12.2(33)SRE1',
	'12.2(33)SRE2',
	'12.2(33)SRE3',
	'12.2(33)SRE4',
	'12.2(33)SRE',
	'12.2(33)SRE0a',
	'12.2(33)SRE5',
	'12.2(33)SRE6',
	'12.2(33)SRE8',
	'12.2(33)SRE7',
	'12.2(33)SRE9',
	'12.2(33)SRE7a',
	'12.2(33)SRE10',
	'12.2(33)SRE11',
	'12.2(33)SRE9a',
	'12.2(33)SRE12',
	'12.2(33)SRE13',
	'12.2(33)SRE14',
	'12.2(33)SRE15',
	'12.2(33)SRE15a',
	'15.0(1)S2',
	'15.0(1)S1',
	'15.0(1)S',
	'15.0(1)S3a',
	'15.0(1)S4',
	'15.0(1)S5',
	'15.0(1)S4a',
	'12.2(33)IRD',
	'12.2(33)IRE',
	'12.2(33)IRE2',
	'12.2(33)IRE1',
	'15.2(1)S',
	'15.2(2)S',
	'15.2(1)S1',
	'15.2(4)S',
	'15.2(1)S2',
	'15.2(2)S1',
	'15.2(2)S2',
	'15.2(4)S1',
	'15.2(4)S4',
	'15.2(4)S6',
	'15.2(4)S2',
	'15.2(4)S5',
	'15.2(4)S3',
	'15.2(4)S3a',
	'15.2(4)S4a',
	'15.2(4)S7',
	'15.2(4)S8',
	'15.0(1)EY',
	'15.0(1)EY2',
	'12.3(9)M0',
	'12.3(9)M1',
	'12.2(27)SBK9',
	'12.2(33)ZZ',
	'15.1(2)S',
	'15.1(1)S',
	'15.1(1)S1',
	'15.1(3)S',
	'15.1(1)S2',
	'15.1(2)S1',
	'15.1(2)S2',
	'15.1(3)S1',
	'15.1(3)S0a',
	'15.1(3)S2',
	'15.1(3)S4',
	'15.1(3)S3',
	'15.1(3)S5',
	'15.1(3)S6',
	'15.1(3)S5a',
	'15.1(3)S7',
	'12.2(33)IRF',
	'15.0(1)SY',
	'15.0(1)SY1',
	'15.0(1)SY2',
	'15.0(1)SY3',
	'15.0(1)SY4',
	'15.0(1)SY5',
	'15.0(1)SY6',
	'15.0(1)SY7',
	'15.0(1)SY8',
	'15.0(1)SY7a',
	'15.0(1)SY9',
	'15.0(1)SY10',
	'12.2(33)SXJ',
	'12.2(33)SXJ1',
	'12.2(33)SXJ2',
	'12.2(33)SXJ3',
	'12.2(33)SXJ4',
	'12.2(33)SXJ5',
	'12.2(33)SXJ6',
	'12.2(33)SXJ7',
	'12.2(33)SXJ8',
	'12.2(33)SXJ9',
	'12.2(33)SXJ10',
	'12.2(33)SCF',
	'12.2(33)SCF1',
	'12.2(33)SCF2',
	'12.2(33)SCF3',
	'12.2(33)SCF4',
	'12.2(33)SCF5',
	'12.2(33)SCE',
	'12.2(33)SCE1',
	'12.2(33)SCE2',
	'12.2(33)SCE3',
	'12.2(33)SCE4',
	'12.2(33)SCE5',
	'12.2(33)SCE6',
	'15.0(2)SG11a',
	'12.2(33)IRG',
	'12.2(33)IRG1',
	'15.0(2)EX2',
	'15.0(2)EX8',
	'12.2(33)SCG',
	'12.2(33)SCG1',
	'12.2(33)SCG2',
	'12.2(33)SCG3',
	'12.2(33)SCG4',
	'12.2(33)SCG5',
	'12.2(33)SCG6',
	'12.2(33)SCG7',
	'12.2(33)IRH',
	'12.2(33)IRH1',
	'15.1(1)SY',
	'15.1(1)SY1',
	'15.1(2)SY',
	'15.1(2)SY1',
	'15.1(2)SY2',
	'15.1(1)SY2',
	'15.1(1)SY3',
	'15.1(2)SY3',
	'15.1(1)SY4',
	'15.1(2)SY4',
	'15.1(1)SY5',
	'15.1(2)SY5',
	'15.1(2)SY4a',
	'15.1(1)SY6',
	'15.1(2)SY6',
	'15.1(2)SY7',
	'15.1(2)SY8',
	'15.1(2)SY9',
	'15.1(2)SY10',
	'15.1(2)SY11',
	'15.1(2)SY12',
	'15.1(2)SY13',
	'15.1(2)SY14',
	'15.3(1)S',
	'15.3(2)S',
	'15.3(3)S',
	'15.3(1)S2',
	'15.3(1)S1',
	'15.3(2)S2',
	'15.3(2)S1',
	'15.3(3)S1',
	'15.3(3)S2',
	'15.3(3)S3',
	'15.3(3)S6',
	'15.3(3)S4',
	'15.3(3)S5',
	'15.3(3)S2a',
	'15.3(3)S7',
	'15.3(3)S8',
	'15.3(3)S6a',
	'15.3(3)S9',
	'15.3(3)S10',
	'15.3(3)S8a',
	'12.2(33)SCH',
	'12.2(33)SCH1',
	'12.2(33)SCH2',
	'12.2(33)SCH3',
	'12.2(33)SCH2a',
	'12.2(33)SCH4',
	'12.2(33)SCH5',
	'12.2(33)SCH6',
	'15.4(1)S',
	'15.4(2)S',
	'15.4(3)S',
	'15.4(1)S1',
	'15.4(1)S2',
	'15.4(2)S1',
	'15.4(1)S3',
	'15.4(3)S1',
	'15.4(2)S2',
	'15.4(3)S2',
	'15.4(3)S3',
	'15.4(1)S4',
	'15.4(2)S3',
	'15.4(2)S4',
	'15.4(3)S4',
	'15.4(3)S5',
	'15.4(3)S6',
	'15.4(3)S7',
	'15.4(3)S6a',
	'15.4(3)S8',
	'15.4(3)S9',
	'15.4(3)S10',
	'15.2(2)JAX1',
	'15.2(2)SC1',
	'15.2(2)SC3',
	'15.2(2)SC4',
	'15.2(1)SY',
	'15.2(1)SY1',
	'15.2(1)SY0a',
	'15.2(1)SY2',
	'15.2(2)SY',
	'15.2(1)SY1a',
	'15.2(2)SY1',
	'15.2(2)SY2',
	'15.2(1)SY3',
	'15.2(1)SY4',
	'15.2(2)SY3',
	'15.2(1)SY5',
	'15.2(1)SY6',
	'15.2(1)SY7',
	'15.2(1)SY8',
	'15.2(4)JAZ1',
	'15.5(1)S',
	'15.5(2)S',
	'15.5(1)S1',
	'15.5(3)S',
	'15.5(1)S2',
	'15.5(1)S3',
	'15.5(2)S1',
	'15.5(2)S2',
	'15.5(3)S1',
	'15.5(2)S3',
	'15.5(3)S2',
	'15.5(3)S0a',
	'15.5(3)S3',
	'15.5(1)S4',
	'15.5(2)S4',
	'15.5(3)S4',
	'15.5(3)S5',
	'15.5(3)S6',
	'15.5(3)S7',
	'15.5(3)S6b',
	'15.5(3)S8',
	'15.5(3)S9',
	'12.2(33)SCI',
	'12.2(33)SCI1',
	'12.2(33)SCI1a',
	'12.2(33)SCI2',
	'12.2(33)SCI3',
	'12.2(33)SCI2a',
	'15.3(3)JAA1',
	'15.3(1)SY',
	'15.3(0)SY',
	'15.3(1)SY1',
	'15.3(1)SY2',
	'12.2(33)SCJ',
	'12.2(33)SCJ1a',
	'12.2(33)SCJ2',
	'12.2(33)SCJ2a',
	'12.2(33)SCJ2b',
	'12.2(33)SCJ2c',
	'12.2(33)SCJ3',
	'15.6(2)SP3b',
	'15.4(1)SY',
	'15.4(1)SY1',
	'15.4(1)SY2',
	'15.4(1)SY3',
	'15.4(1)SY4',
	'15.5(1)SY',
	'15.5(1)SY1',
	'15.5(1)SY2',
	'15.5(1)SY3',
	'15.1(3)SVR'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ip_identd'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvm01689',
  'cmds'	   , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
