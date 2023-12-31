#TRUSTED 38f83b6ac937910c2ee4dd2987b9133c308a65cc2dceb736228e63f3c6a60c2d59e568a1d37c3bae2e6121f8bd4723f9637900e8f31e0429876ce96d81015826eda8b2e8a3004f8402cbd734596d2b16f5b3bc1c2768dc2f82762f066048f6ba4fcf21f9f5502965b014e1bff310a96fc183799a61d0a41decd8cef0d33ea8311f959bf01ae6a153c19838f49cea2e54c07d458f6f15b8ad20e3c4bebe102824533895aeaec821fd18d0e88deca8d3622d47047d4e642d4ba497477ff8804b31b4fb014a23aaf8ee668a59ef3c48b040a86b16b67bb73a37b13b0249c8f20a7fb9352d149e6845bbe5e20d6b55ec75c9ed1826c3b7b354c9f7879c5ca3b31d49503a91470aaa8f702e8d2c6b6a5f5fe76391f168cdeb6f4de9cf3207838d6deb632f4dcef9241a36113d6588555e6c9b25f6fcf48aa50e56d204a33177cef6e2e190febaada153aeb28090481a1dc603cf48145570df6df9ab0e1a4ec0afa340a13880cf6dc4d2816b0772f2f90a5811e0070bab68963337243de72153a2a5bc66f1f90be6db53b5b5647821d32a57b40d26ebcdb6868f5d646c18409460c33ffda669dba150af564baea3d9c0c5364e91eed3feff2fba44afc8a8af62001e2cef2621d3bb42b7c2dbe60ef82862c6bd0eb4eba897991f0934251922a72ea39b9b214436c199593a6da9f0ce48c1244e527ff3b45f23403720fd7a7f1ee6c14f
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141116);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3477");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu10399");
  script_xref(name:"CISCO-SA", value:"cisco-sa-info-disclosure-V4BmJBNF");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS Software Information Disclosure (cisco-sa-info-disclosure-V4BmJBNF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS is affected by a information disclosure vulnerability. An authenticated,
local attacker to access files from the flash: filesystem due to insufficient application of restrictions during the
execution of a specific command.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-info-disclosure-V4BmJBNF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b353e4e6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu10399");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu10399");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3477");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list=make_list(
  '12.2(33)CX',
  '12.2(33)CY',
  '12.2(33)CY1',
  '12.2(33)CY2',
  '12.2(33)MRA',
  '12.2(33)MRB',
  '12.2(33)MRB1',
  '12.2(33)MRB2',
  '12.2(33)MRB3',
  '12.2(33)MRB4',
  '12.2(33)MRB5',
  '12.2(33)MRB6',
  '12.2(33)SB10',
  '12.2(33)SB11',
  '12.2(33)SB12',
  '12.2(33)SB13',
  '12.2(33)SB14',
  '12.2(33)SB15',
  '12.2(33)SB16',
  '12.2(33)SB17',
  '12.2(33)SB7',
  '12.2(33)SB8',
  '12.2(33)SB8a',
  '12.2(33)SB8b',
  '12.2(33)SB8c',
  '12.2(33)SB8d',
  '12.2(33)SB8e',
  '12.2(33)SB8f',
  '12.2(33)SB8g',
  '12.2(33)SB9',
  '12.2(33)SCE',
  '12.2(33)SCE1',
  '12.2(33)SCE2',
  '12.2(33)SCE3',
  '12.2(33)SCE4',
  '12.2(33)SCE5',
  '12.2(33)SCE6',
  '12.2(33)SCF',
  '12.2(33)SCF1',
  '12.2(33)SCF2',
  '12.2(33)SCF3',
  '12.2(33)SCF4',
  '12.2(33)SCF5',
  '12.2(33)SCG',
  '12.2(33)SCG1',
  '12.2(33)SCG2',
  '12.2(33)SCG3',
  '12.2(33)SCG4',
  '12.2(33)SCG5',
  '12.2(33)SCG6',
  '12.2(33)SCG7',
  '12.2(33)SCH',
  '12.2(33)SCH0a',
  '12.2(33)SCH1',
  '12.2(33)SCH2',
  '12.2(33)SCH2a',
  '12.2(33)SCH3',
  '12.2(33)SCH4',
  '12.2(33)SCH5',
  '12.2(33)SCH6',
  '12.2(33)SCI',
  '12.2(33)SCI1',
  '12.2(33)SCI1a',
  '12.2(33)SCI2',
  '12.2(33)SCI2a',
  '12.2(33)SCI3',
  '12.2(33)SCJ',
  '12.2(33)SCJ1a',
  '12.2(33)SCJ2',
  '12.2(33)SCJ2a',
  '12.2(33)SCJ2b',
  '12.2(33)SCJ2c',
  '12.2(33)SCJ3',
  '12.2(33)SCJ4',
  '12.2(33)SRC4',
  '12.2(33)SRC5',
  '12.2(33)SRC6',
  '12.2(33)SRD',
  '12.2(33)SRD1',
  '12.2(33)SRD2',
  '12.2(33)SRD2a',
  '12.2(33)SRD3',
  '12.2(33)SRD4',
  '12.2(33)SRD4a',
  '12.2(33)SRD5',
  '12.2(33)SRD6',
  '12.2(33)SRD7',
  '12.2(33)SRD8',
  '12.2(33)SRE',
  '12.2(33)SRE0a',
  '12.2(33)SRE1',
  '12.2(33)SRE10',
  '12.2(33)SRE11',
  '12.2(33)SRE12',
  '12.2(33)SRE13',
  '12.2(33)SRE14',
  '12.2(33)SRE15',
  '12.2(33)SRE15a',
  '12.2(33)SRE2',
  '12.2(33)SRE3',
  '12.2(33)SRE4',
  '12.2(33)SRE5',
  '12.2(33)SRE6',
  '12.2(33)SRE7',
  '12.2(33)SRE7a',
  '12.2(33)SRE8',
  '12.2(33)SRE9',
  '12.2(33)SRE9a',
  '12.2(33)SXI',
  '12.2(33)SXI1',
  '12.2(33)SXI10',
  '12.2(33)SXI11',
  '12.2(33)SXI12',
  '12.2(33)SXI13',
  '12.2(33)SXI14',
  '12.2(33)SXI2',
  '12.2(33)SXI2a',
  '12.2(33)SXI3',
  '12.2(33)SXI3a',
  '12.2(33)SXI3z',
  '12.2(33)SXI4',
  '12.2(33)SXI4a',
  '12.2(33)SXI5',
  '12.2(33)SXI5a',
  '12.2(33)SXI6',
  '12.2(33)SXI7',
  '12.2(33)SXI8',
  '12.2(33)SXI8a',
  '12.2(33)SXI9',
  '12.2(33)SXI9a',
  '12.2(33)SXJ',
  '12.2(33)SXJ1',
  '12.2(33)SXJ10',
  '12.2(33)SXJ2',
  '12.2(33)SXJ3',
  '12.2(33)SXJ4',
  '12.2(33)SXJ5',
  '12.2(33)SXJ6',
  '12.2(33)SXJ7',
  '12.2(33)SXJ8',
  '12.2(33)SXJ9',
  '12.2(33)ZI',
  '12.2(33)ZZ',
  '12.2(54)SE',
  '12.2(54)SG',
  '12.2(54)SG1',
  '12.2(54)WO',
  '12.2(54)XO',
  '12.2(55)EX',
  '12.2(55)EX1',
  '12.2(55)EX2',
  '12.2(55)EX3',
  '12.2(55)EY',
  '12.2(55)EZ',
  '12.2(55)SE',
  '12.2(55)SE1',
  '12.2(55)SE10',
  '12.2(55)SE11',
  '12.2(55)SE12',
  '12.2(55)SE13',
  '12.2(55)SE2',
  '12.2(55)SE3',
  '12.2(55)SE4',
  '12.2(55)SE5',
  '12.2(55)SE6',
  '12.2(55)SE7',
  '12.2(55)SE8',
  '12.2(55)SE9',
  '12.2(58)EX',
  '12.2(58)EY',
  '12.2(58)EY1',
  '12.2(58)EY2',
  '12.2(58)EZ',
  '12.2(58)SE',
  '12.2(58)SE1',
  '12.2(58)SE2',
  '12.2(6)I1',
  '12.2(60)EZ',
  '12.2(60)EZ1',
  '12.2(60)EZ10',
  '12.2(60)EZ11',
  '12.2(60)EZ12',
  '12.2(60)EZ13',
  '12.2(60)EZ14',
  '12.2(60)EZ2',
  '12.2(60)EZ3',
  '12.2(60)EZ4',
  '12.2(60)EZ5',
  '12.2(60)EZ6',
  '12.2(60)EZ7',
  '12.2(60)EZ8',
  '12.2(60)EZ9',
  '12.4(15)MD',
  '12.4(15)MD1',
  '12.4(15)MD1a',
  '12.4(15)MD2',
  '12.4(15)MD3',
  '12.4(15)MD4',
  '12.4(15)MD5',
  '12.4(15)XQ',
  '12.4(15)XQ1',
  '12.4(15)XQ2',
  '12.4(15)XQ2a',
  '12.4(15)XQ2b',
  '12.4(15)XQ2c',
  '12.4(15)XQ2d',
  '12.4(15)XQ3',
  '12.4(15)XQ4',
  '12.4(15)XQ5',
  '12.4(15)XQ6',
  '12.4(15)XQ7',
  '12.4(15)XQ8',
  '12.4(15)XR',
  '12.4(15)XR1',
  '12.4(15)XR10',
  '12.4(15)XR2',
  '12.4(15)XR3',
  '12.4(15)XR4',
  '12.4(15)XR5',
  '12.4(15)XR6',
  '12.4(15)XR7',
  '12.4(15)XR8',
  '12.4(15)XR9',
  '12.4(15)XZ',
  '12.4(15)XZ1',
  '12.4(15)XZ2',
  '12.4(19)',
  '12.4(19)MR',
  '12.4(19)MR1',
  '12.4(19)MR2',
  '12.4(19)MR3',
  '12.4(19b)',
  '12.4(20)MR',
  '12.4(20)MR1',
  '12.4(20)MR2',
  '12.4(20)MRB',
  '12.4(20)MRB1',
  '12.4(20)T',
  '12.4(20)T1',
  '12.4(20)T2',
  '12.4(20)T3',
  '12.4(20)T4',
  '12.4(20)T5',
  '12.4(20)T5a',
  '12.4(20)T6',
  '12.4(20)T9',
  '12.4(21)',
  '12.4(21a)',
  '12.4(21a)JA',
  '12.4(21a)JA1',
  '12.4(21a)JA2',
  '12.4(21a)JHA',
  '12.4(21a)JHC',
  '12.4(21a)JX',
  '12.4(21a)JY',
  '12.4(21a)M1',
  '12.4(22)MD',
  '12.4(22)MD1',
  '12.4(22)MD2',
  '12.4(22)MDA',
  '12.4(22)MDA1',
  '12.4(22)MDA2',
  '12.4(22)MDA3',
  '12.4(22)MDA4',
  '12.4(22)MDA5',
  '12.4(22)MDA6',
  '12.4(22)T',
  '12.4(22)T1',
  '12.4(22)T2',
  '12.4(22)T3',
  '12.4(22)T4',
  '12.4(22)T5',
  '12.4(22)XR1',
  '12.4(22)XR10',
  '12.4(22)XR11',
  '12.4(22)XR12',
  '12.4(22)XR2',
  '12.4(22)XR3',
  '12.4(22)XR4',
  '12.4(22)XR5',
  '12.4(22)XR6',
  '12.4(22)XR7',
  '12.4(22)XR8',
  '12.4(22)XR9',
  '12.4(23)',
  '12.4(23a)',
  '12.4(23b)',
  '12.4(23b)M1',
  '12.4(23c)',
  '12.4(23c)JA',
  '12.4(23c)JA10',
  '12.4(23c)JA2',
  '12.4(23c)JA3',
  '12.4(23c)JA4',
  '12.4(23c)JA5',
  '12.4(23c)JA6',
  '12.4(23c)JA7',
  '12.4(23c)JA8',
  '12.4(23c)JA9',
  '12.4(23c)JY',
  '12.4(23d)',
  '12.4(23e)',
  '12.4(24)MD',
  '12.4(24)MD1',
  '12.4(24)MD2',
  '12.4(24)MD3',
  '12.4(24)MD4',
  '12.4(24)MD5',
  '12.4(24)MD6',
  '12.4(24)MD7',
  '12.4(24)MDA',
  '12.4(24)MDA1',
  '12.4(24)MDA10',
  '12.4(24)MDA11',
  '12.4(24)MDA12',
  '12.4(24)MDA13',
  '12.4(24)MDA2',
  '12.4(24)MDA3',
  '12.4(24)MDA4',
  '12.4(24)MDA5',
  '12.4(24)MDA6',
  '12.4(24)MDA7',
  '12.4(24)MDA8',
  '12.4(24)MDA9',
  '12.4(24)MDB',
  '12.4(24)MDB1',
  '12.4(24)MDB10',
  '12.4(24)MDB11',
  '12.4(24)MDB12',
  '12.4(24)MDB13',
  '12.4(24)MDB14',
  '12.4(24)MDB15',
  '12.4(24)MDB16',
  '12.4(24)MDB17',
  '12.4(24)MDB18',
  '12.4(24)MDB19',
  '12.4(24)MDB3',
  '12.4(24)MDB4',
  '12.4(24)MDB5',
  '12.4(24)MDB5a',
  '12.4(24)MDB6',
  '12.4(24)MDB7',
  '12.4(24)MDB8',
  '12.4(24)MDB9',
  '12.4(24)T',
  '12.4(24)T1',
  '12.4(24)T10',
  '12.4(24)T11',
  '12.4(24)T12',
  '12.4(24)T2',
  '12.4(24)T3',
  '12.4(24)T3e',
  '12.4(24)T3f',
  '12.4(24)T4',
  '12.4(24)T4a',
  '12.4(24)T4b',
  '12.4(24)T4c',
  '12.4(24)T4d',
  '12.4(24)T4e',
  '12.4(24)T4f',
  '12.4(24)T4g',
  '12.4(24)T4h',
  '12.4(24)T4i',
  '12.4(24)T4j',
  '12.4(24)T4k',
  '12.4(24)T4l',
  '12.4(24)T4m',
  '12.4(24)T4n',
  '12.4(24)T4o',
  '12.4(24)T5',
  '12.4(24)T6',
  '12.4(24)T7',
  '12.4(24)T8',
  '12.4(24)T9',
  '12.4(24)YG',
  '12.4(24)YG1',
  '12.4(24)YG2',
  '12.4(24)YG3',
  '12.4(24)YG4',
  '12.4(24)YS',
  '12.4(24)YS1',
  '12.4(24)YS10',
  '12.4(24)YS2',
  '12.4(24)YS3',
  '12.4(24)YS4',
  '12.4(24)YS5',
  '12.4(24)YS6',
  '12.4(24)YS7',
  '12.4(24)YS8',
  '12.4(24)YS8a',
  '12.4(24)YS9',
  '12.4(25)',
  '12.4(25a)',
  '12.4(25b)',
  '12.4(25c)',
  '12.4(25d)',
  '12.4(25d)JA',
  '12.4(25d)JA1',
  '12.4(25d)JA2',
  '12.4(25d)JAX',
  '12.4(25d)JAX1',
  '12.4(25d)JB',
  '12.4(25e)',
  '12.4(25e)JA',
  '12.4(25e)JA1',
  '12.4(25e)JAL',
  '12.4(25e)JAL1',
  '12.4(25e)JAL1a',
  '12.4(25e)JAL2',
  '12.4(25e)JAM',
  '12.4(25e)JAM2',
  '12.4(25e)JAM3',
  '12.4(25e)JAM4',
  '12.4(25e)JAM5',
  '12.4(25e)JAM6',
  '12.4(25e)JAO',
  '12.4(25e)JAO1',
  '12.4(25e)JAO2',
  '12.4(25e)JAO3',
  '12.4(25e)JAO4',
  '12.4(25e)JAO5',
  '12.4(25e)JAO5m',
  '12.4(25e)JAO6',
  '12.4(25e)JAP',
  '12.4(25e)JAP1',
  '12.4(25e)JAP10',
  '12.4(25e)JAP11',
  '12.4(25e)JAP12',
  '12.4(25e)JAP1n',
  '12.4(25e)JAP4',
  '12.4(25e)JAP5',
  '12.4(25e)JAP6',
  '12.4(25e)JAP7',
  '12.4(25e)JAP8',
  '12.4(25e)JAX',
  '12.4(25e)JAX1',
  '12.4(25e)JAX2',
  '12.4(25e)JAZ',
  '12.4(25e)JX',
  '12.4(25f)',
  '12.4(25g)',
  '15.0(1)EX',
  '15.0(1)EY',
  '15.0(1)EY1',
  '15.0(1)EY2',
  '15.0(1)M',
  '15.0(1)M1',
  '15.0(1)M10',
  '15.0(1)M2',
  '15.0(1)M3',
  '15.0(1)M4',
  '15.0(1)M5',
  '15.0(1)M6',
  '15.0(1)M6a',
  '15.0(1)M7',
  '15.0(1)M8',
  '15.0(1)M9',
  '15.0(1)MR',
  '15.0(1)S',
  '15.0(1)S1',
  '15.0(1)S2',
  '15.0(1)S3a',
  '15.0(1)S4',
  '15.0(1)S4a',
  '15.0(1)S5',
  '15.0(1)S6',
  '15.0(1)SE',
  '15.0(1)SE1',
  '15.0(1)SE2',
  '15.0(1)SE3',
  '15.0(1)SY',
  '15.0(1)SY1',
  '15.0(1)SY10',
  '15.0(1)SY2',
  '15.0(1)SY3',
  '15.0(1)SY4',
  '15.0(1)SY5',
  '15.0(1)SY6',
  '15.0(1)SY7',
  '15.0(1)SY7a',
  '15.0(1)SY8',
  '15.0(1)SY9',
  '15.0(1)XA',
  '15.0(1)XA1',
  '15.0(1)XA2',
  '15.0(1)XA3',
  '15.0(1)XA4',
  '15.0(1)XA5',
  '15.0(1)XO',
  '15.0(1)XO1',
  '15.0(2)EJ',
  '15.0(2)EJ1',
  '15.0(2)EK',
  '15.0(2)EK1',
  '15.0(2)EX',
  '15.0(2)EX1',
  '15.0(2)EX10',
  '15.0(2)EX11',
  '15.0(2)EX12',
  '15.0(2)EX13',
  '15.0(2)EX2',
  '15.0(2)EX3',
  '15.0(2)EX4',
  '15.0(2)EX5',
  '15.0(2)EX6',
  '15.0(2)EX7',
  '15.0(2)EX8',
  '15.0(2)EY',
  '15.0(2)EY1',
  '15.0(2)EY2',
  '15.0(2)EY3',
  '15.0(2)EZ',
  '15.0(2)MR',
  '15.0(2)SE',
  '15.0(2)SE1',
  '15.0(2)SE10',
  '15.0(2)SE10a',
  '15.0(2)SE11',
  '15.0(2)SE12',
  '15.0(2)SE13',
  '15.0(2)SE2',
  '15.0(2)SE3',
  '15.0(2)SE4',
  '15.0(2)SE5',
  '15.0(2)SE6',
  '15.0(2)SE7',
  '15.0(2)SE8',
  '15.0(2)SE9',
  '15.0(2)SG',
  '15.0(2)SG1',
  '15.0(2)SG10',
  '15.0(2)SG11',
  '15.0(2)SG2',
  '15.0(2)SG3',
  '15.0(2)SG4',
  '15.0(2)SG5',
  '15.0(2)SG6',
  '15.0(2)SG7',
  '15.0(2)SG8',
  '15.0(2)SG9',
  '15.0(2)SQD',
  '15.0(2)SQD1',
  '15.0(2)SQD2',
  '15.0(2)SQD3',
  '15.0(2)SQD4',
  '15.0(2)SQD5',
  '15.0(2)SQD6',
  '15.0(2)SQD7',
  '15.0(2)SQD8',
  '15.0(2)XO',
  '15.0(2a)EX5',
  '15.0(2a)SE9',
  '15.1(1)S',
  '15.1(1)S1',
  '15.1(1)S2',
  '15.1(1)SG',
  '15.1(1)SG1',
  '15.1(1)SG2',
  '15.1(1)SY',
  '15.1(1)SY1',
  '15.1(1)SY2',
  '15.1(1)SY3',
  '15.1(1)SY4',
  '15.1(1)SY5',
  '15.1(1)SY6',
  '15.1(1)T',
  '15.1(1)T1',
  '15.1(1)T2',
  '15.1(1)T3',
  '15.1(1)T4',
  '15.1(1)T5',
  '15.1(1)XB',
  '15.1(1)XB1',
  '15.1(1)XB2',
  '15.1(1)XB3',
  '15.1(2)GC',
  '15.1(2)GC1',
  '15.1(2)GC2',
  '15.1(2)S',
  '15.1(2)S1',
  '15.1(2)S2',
  '15.1(2)SG',
  '15.1(2)SG1',
  '15.1(2)SG2',
  '15.1(2)SG3',
  '15.1(2)SG4',
  '15.1(2)SG5',
  '15.1(2)SG6',
  '15.1(2)SG7',
  '15.1(2)SG8',
  '15.1(2)SY',
  '15.1(2)SY1',
  '15.1(2)SY10',
  '15.1(2)SY11',
  '15.1(2)SY12',
  '15.1(2)SY13',
  '15.1(2)SY14',
  '15.1(2)SY15',
  '15.1(2)SY16',
  '15.1(2)SY2',
  '15.1(2)SY3',
  '15.1(2)SY4',
  '15.1(2)SY4a',
  '15.1(2)SY5',
  '15.1(2)SY6',
  '15.1(2)SY7',
  '15.1(2)SY8',
  '15.1(2)SY9',
  '15.1(2)T',
  '15.1(2)T0a',
  '15.1(2)T1',
  '15.1(2)T2',
  '15.1(2)T2a',
  '15.1(2)T3',
  '15.1(2)T4',
  '15.1(2)T5',
  '15.1(3)MRA',
  '15.1(3)MRA1',
  '15.1(3)MRA2',
  '15.1(3)MRA3',
  '15.1(3)MRA4',
  '15.1(3)S',
  '15.1(3)S0a',
  '15.1(3)S1',
  '15.1(3)S2',
  '15.1(3)S3',
  '15.1(3)S4',
  '15.1(3)S5',
  '15.1(3)S5a',
  '15.1(3)S6',
  '15.1(3)S7',
  '15.1(3)SVB1',
  '15.1(3)SVB2',
  '15.1(3)SVD',
  '15.1(3)SVD1',
  '15.1(3)SVD2',
  '15.1(3)SVD3',
  '15.1(3)SVE',
  '15.1(3)SVF',
  '15.1(3)SVF1',
  '15.1(3)SVF2',
  '15.1(3)SVF2a',
  '15.1(3)SVF4b',
  '15.1(3)SVF4c',
  '15.1(3)SVF4d',
  '15.1(3)SVF4e',
  '15.1(3)SVF4f',
  '15.1(3)SVG',
  '15.1(3)SVG1a',
  '15.1(3)SVG1b',
  '15.1(3)SVG1c',
  '15.1(3)SVG2',
  '15.1(3)SVG2a',
  '15.1(3)SVG3',
  '15.1(3)SVG3a',
  '15.1(3)SVG3b',
  '15.1(3)SVG3c',
  '15.1(3)SVH',
  '15.1(3)SVH2',
  '15.1(3)SVH4',
  '15.1(3)SVH4a',
  '15.1(3)SVI1a',
  '15.1(3)SVI2',
  '15.1(3)SVI2a',
  '15.1(3)SVI3',
  '15.1(3)SVI31a',
  '15.1(3)SVI31b',
  '15.1(3)SVI3b',
  '15.1(3)SVI3c',
  '15.1(3)SVJ',
  '15.1(3)SVJ2',
  '15.1(3)SVR1',
  '15.1(3)SVR2',
  '15.1(3)SVR3',
  '15.1(3)SVS',
  '15.1(3)SVS1',
  '15.1(3)T',
  '15.1(3)T1',
  '15.1(3)T2',
  '15.1(3)T3',
  '15.1(3)T4',
  '15.1(4)GC',
  '15.1(4)GC1',
  '15.1(4)GC2',
  '15.1(4)M',
  '15.1(4)M0a',
  '15.1(4)M0b',
  '15.1(4)M1',
  '15.1(4)M10',
  '15.1(4)M12a',
  '15.1(4)M2',
  '15.1(4)M3',
  '15.1(4)M3a',
  '15.1(4)M4',
  '15.1(4)M5',
  '15.1(4)M6',
  '15.1(4)M7',
  '15.1(4)M8',
  '15.1(4)M9',
  '15.1(4)XB4',
  '15.1(4)XB5',
  '15.1(4)XB5a',
  '15.1(4)XB6',
  '15.1(4)XB7',
  '15.1(4)XB8',
  '15.1(4)XB8a',
  '15.2(1)E',
  '15.2(1)E1',
  '15.2(1)E2',
  '15.2(1)E3',
  '15.2(1)EY',
  '15.2(1)S',
  '15.2(1)S1',
  '15.2(1)S2',
  '15.2(1)SC1a',
  '15.2(1)SD1',
  '15.2(1)SD2',
  '15.2(1)SD3',
  '15.2(1)SD4',
  '15.2(1)SD6',
  '15.2(1)SD6a',
  '15.2(1)SD7',
  '15.2(1)SD8',
  '15.2(1)SY',
  '15.2(1)SY0a',
  '15.2(1)SY1',
  '15.2(1)SY1a',
  '15.2(1)SY2',
  '15.2(1)SY3',
  '15.2(1)SY4',
  '15.2(1)SY5',
  '15.2(1)SY6',
  '15.2(1)SY7',
  '15.2(1)SY8',
  '15.2(2)E',
  '15.2(2)E1',
  '15.2(2)E10',
  '15.2(2)E2',
  '15.2(2)E3',
  '15.2(2)E4',
  '15.2(2)E5',
  '15.2(2)E5a',
  '15.2(2)E5b',
  '15.2(2)E6',
  '15.2(2)E7',
  '15.2(2)E7b',
  '15.2(2)E8',
  '15.2(2)E9',
  '15.2(2)E9a',
  '15.2(2)EA',
  '15.2(2)EA1',
  '15.2(2)EA2',
  '15.2(2)EA3',
  '15.2(2)EB',
  '15.2(2)EB1',
  '15.2(2)EB2',
  '15.2(2)S',
  '15.2(2)S0a',
  '15.2(2)S0c',
  '15.2(2)S0d',
  '15.2(2)S1',
  '15.2(2)S2',
  '15.2(2)SC',
  '15.2(2)SC1',
  '15.2(2)SC3',
  '15.2(2)SC4',
  '15.2(2)SY',
  '15.2(2)SY1',
  '15.2(2)SY2',
  '15.2(2)SY3',
  '15.2(2a)E1',
  '15.2(2a)E2',
  '15.2(2b)E',
  '15.2(3)E',
  '15.2(3)E1',
  '15.2(3)E2',
  '15.2(3)E3',
  '15.2(3)E4',
  '15.2(3)E5',
  '15.2(3)EA',
  '15.2(3a)E',
  '15.2(3m)E2',
  '15.2(3m)E7',
  '15.2(3m)E8',
  '15.2(4)E',
  '15.2(4)E1',
  '15.2(4)E10',
  '15.2(4)E2',
  '15.2(4)E3',
  '15.2(4)E4',
  '15.2(4)E5',
  '15.2(4)E5a',
  '15.2(4)E6',
  '15.2(4)E7',
  '15.2(4)E8',
  '15.2(4)E9',
  '15.2(4)EA',
  '15.2(4)EA1',
  '15.2(4)EA2',
  '15.2(4)EA3',
  '15.2(4)EA4',
  '15.2(4)EA5',
  '15.2(4)EA6',
  '15.2(4)EA7',
  '15.2(4)EA8',
  '15.2(4)EA9',
  '15.2(4)EA9a',
  '15.2(4)EC1',
  '15.2(4)EC2',
  '15.2(4)S',
  '15.2(4)S0c',
  '15.2(4)S1',
  '15.2(4)S1c',
  '15.2(4)S2',
  '15.2(4)S3',
  '15.2(4)S3a',
  '15.2(4)S4',
  '15.2(4)S4a',
  '15.2(4)S5',
  '15.2(4)S6',
  '15.2(4)S7',
  '15.2(4)S8',
  '15.2(4m)E1',
  '15.2(4m)E2',
  '15.2(4m)E3',
  '15.2(4n)E2',
  '15.2(4o)E2',
  '15.2(4o)E3',
  '15.2(4p)E1',
  '15.2(4q)E1',
  '15.2(4s)E1',
  '15.2(5)E',
  '15.2(5)E1',
  '15.2(5)E2',
  '15.2(5)E2b',
  '15.2(5)E2c',
  '15.2(5)EA',
  '15.2(5)EX',
  '15.2(5a)E',
  '15.2(5a)E1',
  '15.2(5b)E',
  '15.2(5c)E',
  '15.2(6)E',
  '15.2(6)E0a',
  '15.2(6)E0c',
  '15.2(6)E1',
  '15.2(6)E1a',
  '15.2(6)E1s',
  '15.2(6)E2',
  '15.2(6)E2a',
  '15.2(6)E2b',
  '15.2(6)E3',
  '15.2(6)E4',
  '15.2(6)EB',
  '15.2(7)E',
  '15.2(7)E0a',
  '15.2(7)E0b',
  '15.2(7)E0s',
  '15.2(7)E1',
  '15.2(7)E1a',
  '15.2(7)E2',
  '15.2(7a)E0b',
  '15.2(7b)E0b',
  '15.3(0)SY',
  '15.3(1)S',
  '15.3(1)S1',
  '15.3(1)S1e',
  '15.3(1)S2',
  '15.3(1)SY',
  '15.3(1)SY1',
  '15.3(1)SY2',
  '15.3(2)S',
  '15.3(2)S1',
  '15.3(2)S2',
  '15.3(3)JF99',
  '15.3(3)JK99',
  '15.3(3)S',
  '15.3(3)S1',
  '15.3(3)S10',
  '15.3(3)S1a',
  '15.3(3)S2',
  '15.3(3)S2a',
  '15.3(3)S3',
  '15.3(3)S4',
  '15.3(3)S5',
  '15.3(3)S6',
  '15.3(3)S6a',
  '15.3(3)S7',
  '15.3(3)S8',
  '15.3(3)S8a',
  '15.3(3)S9',
  '15.4(1)S',
  '15.4(1)S1',
  '15.4(1)S2',
  '15.4(1)S3',
  '15.4(1)S4',
  '15.4(1)SY',
  '15.4(1)SY1',
  '15.4(1)SY2',
  '15.4(1)SY3',
  '15.4(1)SY4',
  '15.4(2)S',
  '15.4(2)S1',
  '15.4(2)S2',
  '15.4(2)S3',
  '15.4(2)S4',
  '15.4(2)SN',
  '15.4(2)SN1',
  '15.4(3)S',
  '15.4(3)S0d',
  '15.4(3)S0e',
  '15.4(3)S0f',
  '15.4(3)S1',
  '15.4(3)S10',
  '15.4(3)S2',
  '15.4(3)S3',
  '15.4(3)S4',
  '15.4(3)S5',
  '15.4(3)S6',
  '15.4(3)S6a',
  '15.4(3)S7',
  '15.4(3)S8',
  '15.4(3)S9',
  '15.4(3)SN1',
  '15.4(3)SN1a',
  '15.5(1)S',
  '15.5(1)S1',
  '15.5(1)S2',
  '15.5(1)S3',
  '15.5(1)S4',
  '15.5(1)SN',
  '15.5(1)SN1',
  '15.5(1)SY',
  '15.5(1)SY1',
  '15.5(1)SY2',
  '15.5(1)SY3',
  '15.5(1)SY4',
  '15.5(1)SY5',
  '15.5(2)S',
  '15.5(2)S1',
  '15.5(2)S2',
  '15.5(2)S3',
  '15.5(2)S4',
  '15.5(2)SN',
  '15.5(3)S',
  '15.5(3)S0a',
  '15.5(3)S1',
  '15.5(3)S10',
  '15.5(3)S1a',
  '15.5(3)S2',
  '15.5(3)S3',
  '15.5(3)S4',
  '15.5(3)S5',
  '15.5(3)S6',
  '15.5(3)S6a',
  '15.5(3)S6b',
  '15.5(3)S7',
  '15.5(3)S8',
  '15.5(3)S9',
  '15.5(3)S9a',
  '15.5(3)SN',
  '15.5(3)SN0a',
  '15.6(1)S',
  '15.6(1)S1',
  '15.6(1)S2',
  '15.6(1)S3',
  '15.6(1)S4',
  '15.6(1)SN',
  '15.6(1)SN1',
  '15.6(1)SN2',
  '15.6(1)SN3',
  '15.6(2)S',
  '15.6(2)S1',
  '15.6(2)S2',
  '15.6(2)S3',
  '15.6(2)S4',
  '15.6(2)SN',
  '15.6(2)SP',
  '15.6(2)SP1',
  '15.6(2)SP2',
  '15.6(2)SP3',
  '15.6(2)SP4',
  '15.6(2)SP5',
  '15.6(2)SP6',
  '15.6(2)SP7',
  '15.6(2)SP8',
  '15.6(3)SN',
  '15.6(4)SN',
  '15.6(5)SN',
  '15.6(7)SN',
  '15.6(7)SN1',
  '15.6(7)SN2',
  '15.6(7)SN3'
);
    
reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu10399',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);