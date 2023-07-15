#TRUSTED a37dc18e41c8eae1c26e2bd6adaf7222d75071087238f28fbd458e8fed3b1f600ddea3ceb8ac416974e152a5267b3b24b58d55c1e6278bf3c645d3a3d7707172a8a4eaed5c19c8e2b393b8fcbbac0f7db848c7fc368edf31bfc0448f798a20d916281d2f6d71d78163a9c7273cdf6320972a3b995fd5d139da21fb4f37f5b3b4649f8141e1f0fb38d73066712a3f838427213ba5665e6bfa21c1773ce6c65bbdad41c6db56d2cb1df5d5de1318bd121680bc65132ef1d80099729e32e166c7ab2df507822a9e4e7f0c4ebcacf4ab71a4e64cffe499efa9b44b5e1516c7ac12eca69b3936943b50892d6250634813e02be21f9fb1bf24d2a2d25a282b3f725900564d6978880e9bd9fd2f1f4adcab2d3c3ea122e3591b504dd0c71f89cc9374c76c9ceedea90cb530e2b6edd3fe979dbc7271c34d9f90b97adb7b7a4220b3dcdf1479d6353ea9590715f7e9572b6503c30406931bfdb48eaebde53474c51c6b6aa80354f574f03f181f50e14e7c363f1f7f250beac183a22756ffd06e397b03797611dd5c327d4f97bdb9908c78d70b422456671362858fe59c26944cfd6a093782077402348faae5498216bb39a9902b1b155eb1f935222187b73612135aacc3a1690318609021e7add641833f3720c5a58c5c02ff9aea8eae28e1372fb22d79b64882933c7e1308c3dc38bea889a71f772fb5c043e596c620ac85d7e8a7f562
#TRUST-RSA-SHA256 61f122398c71f896cfc55ba5b6adaf9b2077c064825bda6cc780f48a7208a6cb67566a711b6f04548eccdd171c9d63f1a5bb48351d05dfa1f9d62e2341be083534637032749d36a77c8278cd0d917b1b6bfdc3d7c9ce4e88c7c16a6c99f6c1a17f5ea391daa89dbef0884d8df3610ad480a7d2fdd609ec2daae740687afbb6fa8fbcd9a3d848694f1bde1ee3b7550856f6387bf6ce423bc3e6ef8eb81c8ac07c13f284b5561768248d93a0eb9efdd87b5080b94f827ed67fd7c340fd1a998815c4b3c606be71cfcbc39ab1ffa3d2b9047bc69370a035b96792e20b3be7731e2784019f34613fea96dec02feb93812c477fd867efc3da580732b7450413153963c6ff8187303ac2b561c41c8a025c73c6a03143272a9cbd78d6db5fe7a6fb8831ed12052cbc52b3b61e3e671467275fb767428c6e70c0362c01a19c05b50e358358c61271022602d14cc987b8a7acf301272021ec57ff5b5f15d81107020f34859d99caaccca2e1aff8f02b190ad591d01e8ffae8229a6ff223038156f084f19923d82d5ea15fda4baeef3053559183b11d400fb914517352604e8f2106875b623409bc49d399aad87331092fc81fb4371f7f80b6c4aeb4fe3ecb6b94d812c1a794f9dc4412e282a5008946261f4b0dcfcf8275f08ef08740a7d47d2378d9567b0342ba3aaba0a11886d5f66e3787dd6880079cd0ae8a1590bb599c628e0534ce
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109087);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-0172", "CVE-2018-0173", "CVE-2018-0174");
  script_bugtraq_id(103545, 103552, 103554);
  script_xref(name:"TRA", value:"TRA-2018-06");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg62730");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg62754");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh91645");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-dhcpr1");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-dhcpr2");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-dhcpr3");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");

  script_name(english:"Cisco IOS DHCP Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by multiple denial of service
vulnerabilities in the DHCP client implementation when parsing DHCP
packets. An unauthenticated, remote attacker can exploit these issues,
via specially crafted DHCP packets, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-dhcpr1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bfe8b7e0");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-dhcpr2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2af6e16d");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-dhcpr3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?570bb167");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg62730");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg62754");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuh91645");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2018-06");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvg62730, CSCvg62754, and CSCuh91645.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0174");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");
port = get_kb_item("Host/Cisco/IOS/Port");
if (empty_or_null(port))
  port = 0;
  
# Check for vuln versions
if (
  ver == '12.2(53)SE1' ||
  ver == '12.2(55)SE' ||
  ver == '12.2(46)SE' ||
  ver == '12.2(46)SE2' ||
  ver == '12.2(50)SE2' ||
  ver == '12.2(50)SE1' ||
  ver == '12.2(44)SE2' ||
  ver == '12.2(50)SE5' ||
  ver == '12.2(44)SE1' ||
  ver == '12.2(53)SE' ||
  ver == '12.2(44)SE4' ||
  ver == '12.2(55)SE3' ||
  ver == '12.2(55)SE2' ||
  ver == '12.2(44)SE' ||
  ver == '12.2(52)SE' ||
  ver == '12.2(58)SE' ||
  ver == '12.2(50)SE3' ||
  ver == '12.2(55)SE1' ||
  ver == '12.2(44)SE6' ||
  ver == '12.2(44)SE3' ||
ver == '12.2(53)SE2' ||
ver == '12.2(52)SE1' ||
ver == '12.2(46)SE1' ||
ver == '12.2(54)SE' ||
ver == '12.2(44)SE5' ||
ver == '12.2(50)SE4' ||
ver == '12.2(50)SE' ||
ver == '12.2(58)SE1' ||
ver == '12.2(55)SE4' ||
ver == '12.2(58)SE2' ||
ver == '12.2(55)SE5' ||
ver == '12.2(55)SE6' ||
ver == '12.2(55)SE7' ||
ver == '12.2(55)SE8' ||
ver == '12.2(55)SE9' ||
ver == '12.2(55)SE10' ||
ver == '12.2(55)SE11' ||
ver == '12.2(55)SE12' ||
ver == '12.2(55)SE13' ||
ver == '12.2(44)EX' ||
ver == '12.2(53)EX' ||
ver == '12.2(52)EX' ||
ver == '12.2(44)EX1' ||
ver == '12.2(55)EX' ||
ver == '12.2(46)EX' ||
ver == '12.2(52)EX1' ||
ver == '12.2(55)EX1' ||
ver == '12.2(55)EX2' ||
ver == '12.2(55)EX3' ||
ver == '12.2(58)EX' ||
ver == '12.2(46)EY' ||
ver == '12.2(55)EY' ||
ver == '12.2(52)EY1' ||
ver == '12.2(44)EY' ||
ver == '12.2(52)EY' ||
ver == '12.2(53)EY' ||
ver == '12.2(52)EY2' ||
ver == '12.2(52)EY1b' ||
ver == '12.2(52)EY1c' ||
ver == '12.2(58)EY' ||
ver == '12.2(52)EY3' ||
ver == '12.2(52)EY2a' ||
ver == '12.2(58)EY1' ||
ver == '12.2(52)EY4' ||
ver == '12.2(52)EY3a' ||
ver == '12.2(58)EY2' ||
ver == '12.2(58)EZ' ||
ver == '12.2(53)EZ' ||
ver == '12.2(55)EZ' ||
ver == '12.2(60)EZ' ||
ver == '12.2(60)EZ1' ||
ver == '12.2(60)EZ2' ||
ver == '12.2(60)EZ3' ||
ver == '12.2(60)EZ4' ||
ver == '12.2(60)EZ5' ||
ver == '12.2(60)EZ6' ||
ver == '12.2(60)EZ7' ||
ver == '12.2(60)EZ8' ||
ver == '12.2(60)EZ9' ||
ver == '12.2(60)EZ10' ||
ver == '12.2(60)EZ11' ||
ver == '12.2(60)EZ12' ||
ver == '12.2(50)SG3' ||
ver == '12.2(50)SG6' ||
ver == '12.2(53)SG1' ||
ver == '12.2(46)SG' ||
ver == '12.2(53)SG2' ||
ver == '12.2(50)SG5' ||
ver == '12.2(53)SG3' ||
ver == '12.2(50)SG8' ||
ver == '12.2(50)SG2' ||
ver == '12.2(54)SG1' ||
ver == '12.2(50)SG1' ||
ver == '12.2(52)SG' ||
ver == '12.2(54)SG' ||
ver == '12.2(50)SG' ||
ver == '12.2(50)SG7' ||
ver == '12.2(53)SG4' ||
ver == '12.2(50)SG4' ||
ver == '12.2(46)SG1' ||
ver == '12.2(53)SG5' ||
ver == '12.2(53)SG6' ||
ver == '12.2(53)SG7' ||
ver == '12.2(53)SG8' ||
ver == '12.2(53)SG9' ||
ver == '12.2(53)SG10' ||
ver == '12.2(53)SG11' ||
ver == '12.2(33)SRD7' ||
ver == '12.2(33)SRD6' ||
ver == '12.2(33)SRD2a' ||
ver == '12.2(33)SRD4' ||
ver == '12.2(33)SRD5' ||
ver == '12.2(33)SRD3' ||
ver == '12.2(33)SRD2' ||
ver == '12.2(33)SRD1' ||
ver == '12.2(33)SRD' ||
ver == '12.2(33)SRD8' ||
ver == '12.2(52)XO' ||
ver == '12.2(54)XO' ||
ver == '12.2(50)SQ2' ||
ver == '12.2(50)SQ1' ||
ver == '12.2(50)SQ' ||
ver == '12.2(50)SQ3' ||
ver == '12.2(50)SQ4' ||
ver == '12.2(50)SQ5' ||
ver == '12.2(50)SQ6' ||
ver == '12.2(50)SQ7' ||
ver == '12.2(33)SRE1' ||
ver == '12.2(33)SRE2' ||
ver == '12.2(33)SRE3' ||
ver == '12.2(33)SRE4' ||
ver == '12.2(33)SRE' ||
ver == '12.2(33)SRE0a' ||
ver == '12.2(33)SRE5' ||
ver == '12.2(33)SRE6' ||
ver == '12.2(33)SRE8' ||
ver == '12.2(33)SRE7' ||
ver == '12.2(33)SRE9' ||
ver == '12.2(33)SRE7a' ||
ver == '12.2(33)SRE10' ||
ver == '12.2(33)SRE11' ||
ver == '12.2(33)SRE9a' ||
ver == '12.2(33)SRE12' ||
ver == '12.2(33)SRE13' ||
ver == '12.2(33)SRE14' ||
ver == '12.2(33)SRE15' ||
ver == '12.2(33)SRE15a' ||
ver == '15.0(1)XO1' ||
ver == '15.0(1)XO' ||
ver == '15.0(2)XO' ||
ver == '15.0(1)S2' ||
ver == '15.0(1)S1' ||
ver == '15.0(1)S' ||
ver == '15.0(1)S3a' ||
ver == '15.0(1)S4' ||
ver == '15.0(1)S5' ||
ver == '15.0(1)S4a' ||
ver == '15.0(1)S6' ||
ver == '12.2(33)MRA' ||
ver == '12.2(33)MRB5' ||
ver == '12.2(33)MRB2' ||
ver == '12.2(33)MRB1' ||
ver == '12.2(33)MRB4' ||
ver == '12.2(33)MRB' ||
ver == '12.2(33)MRB3' ||
ver == '12.2(33)MRB6' ||
ver == '15.2(1)S' ||
ver == '15.2(2)S' ||
ver == '15.2(1)S1' ||
ver == '15.2(4)S' ||
ver == '15.2(1)S2' ||
ver == '15.2(2)S1' ||
ver == '15.2(2)S2' ||
ver == '15.2(2)S0a' ||
ver == '15.2(2)S0c' ||
ver == '15.2(4)S1' ||
ver == '15.2(4)S4' ||
ver == '15.2(4)S6' ||
ver == '15.2(4)S2' ||
ver == '15.2(4)S5' ||
ver == '15.2(4)S3' ||
ver == '15.2(4)S3a' ||
ver == '15.2(4)S4a' ||
ver == '15.2(4)S7' ||
ver == '15.0(1)EY' ||
ver == '15.0(1)EY1' ||
ver == '15.0(1)EY2' ||
ver == '15.0(2)EY' ||
ver == '15.0(2)EY1' ||
ver == '15.0(2)EY2' ||
ver == '15.0(2)EY3' ||
ver == '12.2(54)WO' ||
ver == '15.1(2)S' ||
ver == '15.1(1)S' ||
ver == '15.1(1)S1' ||
ver == '15.1(3)S' ||
ver == '15.1(1)S2' ||
ver == '15.1(2)S1' ||
ver == '15.1(2)S2' ||
ver == '15.1(3)S1' ||
ver == '15.1(3)S0a' ||
ver == '15.1(3)S2' ||
ver == '15.1(3)S4' ||
ver == '15.1(3)S3' ||
ver == '15.1(3)S5' ||
ver == '15.1(3)S6' ||
ver == '15.1(3)S5a' ||
ver == '15.0(1)SE' ||
ver == '15.0(2)SE' ||
ver == '15.0(1)SE1' ||
ver == '15.0(1)SE2' ||
ver == '15.0(1)SE3' ||
ver == '15.0(2)SE1' ||
ver == '15.0(2)SE2' ||
ver == '15.0(2)SE3' ||
ver == '15.0(2)SE4' ||
ver == '15.0(2)SE5' ||
ver == '15.0(2)SE6' ||
ver == '15.0(2)SE7' ||
ver == '15.0(2)SE8' ||
ver == '15.0(2)SE9' ||
ver == '15.0(2a)SE9' ||
ver == '15.0(2)SE10' ||
ver == '15.0(2)SE11' ||
ver == '15.0(2)SE10a' ||
ver == '15.0(2)SE12' ||
ver == '15.1(1)SG' ||
ver == '15.1(2)SG' ||
ver == '15.1(1)SG1' ||
ver == '15.1(1)SG2' ||
ver == '15.1(2)SG1' ||
ver == '15.1(2)SG2' ||
ver == '15.1(2)SG3' ||
ver == '15.1(2)SG4' ||
ver == '15.1(2)SG5' ||
ver == '15.1(2)SG6' ||
ver == '15.1(2)SG7' ||
ver == '15.1(2)SG8' ||
ver == '15.1(2)SG8a' ||
ver == '15.0(1)MR' ||
ver == '15.0(2)MR' ||
ver == '15.0(2)SG' ||
ver == '15.0(2)SG1' ||
ver == '15.0(2)SG2' ||
ver == '15.0(2)SG3' ||
ver == '15.0(2)SG4' ||
ver == '15.0(2)SG5' ||
ver == '15.0(2)SG6' ||
ver == '15.0(2)SG7' ||
ver == '15.0(2)SG8' ||
ver == '15.0(2)SG9' ||
ver == '15.0(2)SG10' ||
ver == '15.0(2)SG11' ||
ver == '15.1(1)MR' ||
ver == '15.1(1)MR1' ||
ver == '15.1(1)MR2' ||
ver == '15.1(1)MR3' ||
ver == '15.1(3)MR' ||
ver == '15.1(1)MR4' ||
ver == '15.0(1)EX' ||
ver == '15.0(2)EX' ||
ver == '15.0(2)EX1' ||
ver == '15.0(2)EX2' ||
ver == '15.0(2)EX3' ||
ver == '15.0(2)EX4' ||
ver == '15.0(2)EX5' ||
ver == '15.0(2)EX8' ||
ver == '15.0(2a)EX5' ||
ver == '15.0(2)EX10' ||
ver == '15.0(2)EX11' ||
ver == '15.0(2)EX13' ||
ver == '15.0(2)EX12' ||
ver == '15.1(2)EY' ||
ver == '15.1(2)EY1a' ||
ver == '15.1(2)EY2' ||
ver == '15.1(2)EY3' ||
ver == '15.1(2)EY2a' ||
ver == '15.1(2)EY4' ||
ver == '15.1(2)SNG' ||
ver == '15.3(1)S' ||
ver == '15.3(2)S' ||
ver == '15.3(3)S' ||
ver == '15.3(1)S2' ||
ver == '15.3(1)S1' ||
ver == '15.3(2)S2' ||
ver == '15.3(2)S1' ||
ver == '15.3(3)S1' ||
ver == '15.3(3)S2' ||
ver == '15.3(3)S3' ||
ver == '15.3(3)S6' ||
ver == '15.3(3)S4' ||
ver == '15.3(3)S1a' ||
ver == '15.3(3)S5' ||
ver == '15.3(3)S7' ||
ver == '15.3(3)S8' ||
ver == '15.3(3)S9' ||
ver == '15.3(3)S10' ||
ver == '15.3(3)S8a' ||
ver == '15.1(2)SNH' ||
ver == '15.1(2)SNI' ||
ver == '15.1(2)SNI1' ||
ver == '15.2(2)SNG' ||
ver == '15.0(2)EC' ||
ver == '15.0(2)EB' ||
ver == '15.2(1)E' ||
ver == '15.2(2)E' ||
ver == '15.2(1)E1' ||
ver == '15.2(3)E' ||
ver == '15.2(1)E2' ||
ver == '15.2(1)E3' ||
ver == '15.2(2)E1' ||
ver == '15.2(4)E' ||
ver == '15.2(3)E1' ||
ver == '15.2(2)E2' ||
ver == '15.2(2a)E1' ||
ver == '15.2(2)E3' ||
ver == '15.2(2a)E2' ||
ver == '15.2(3)E2' ||
ver == '15.2(3a)E' ||
ver == '15.2(3)E3' ||
ver == '15.2(3m)E2' ||
ver == '15.2(4)E1' ||
ver == '15.2(2)E4' ||
ver == '15.2(2)E5' ||
ver == '15.2(4)E2' ||
ver == '15.2(4m)E1' ||
ver == '15.2(3)E4' ||
ver == '15.2(5)E' ||
ver == '15.2(4)E3' ||
ver == '15.2(2)E6' ||
ver == '15.2(5a)E' ||
ver == '15.2(5)E1' ||
ver == '15.2(5b)E' ||
ver == '15.2(4m)E3' ||
ver == '15.2(3m)E8' ||
ver == '15.2(2)E5a' ||
ver == '15.2(5c)E' ||
ver == '15.2(3)E5' ||
ver == '15.2(2)E5b' ||
ver == '15.2(4n)E2' ||
ver == '15.2(4o)E2' ||
ver == '15.2(5a)E1' ||
ver == '15.2(4)E4' ||
ver == '15.2(2)E7' ||
ver == '15.2(5)E2' ||
ver == '15.2(4p)E1' ||
ver == '15.2(6)E' ||
ver == '15.2(5)E2b' ||
ver == '15.2(4)E5' ||
ver == '15.2(5)E2c' ||
ver == '15.2(2)E8' ||
ver == '15.2(4m)E2' ||
ver == '15.2(4o)E3' ||
ver == '15.2(4q)E1' ||
ver == '15.2(6)E0a' ||
ver == '15.2(6)E0b' ||
ver == '15.2(2)E7b' ||
ver == '15.2(4)E5a' ||
ver == '15.2(6)E0c' ||
ver == '15.2(2)E9' ||
ver == '15.1(3)MRA' ||
ver == '15.1(3)MRA1' ||
ver == '15.1(3)MRA2' ||
ver == '15.1(3)MRA3' ||
ver == '15.1(3)MRA4' ||
ver == '15.2(2)SNH1' ||
ver == '15.0(2)ED' ||
ver == '15.0(2)ED1' ||
ver == '15.4(1)S' ||
ver == '15.4(2)S' ||
ver == '15.4(3)S' ||
ver == '15.4(1)S1' ||
ver == '15.4(1)S2' ||
ver == '15.4(2)S1' ||
ver == '15.4(1)S3' ||
ver == '15.4(3)S1' ||
ver == '15.4(2)S2' ||
ver == '15.4(3)S2' ||
ver == '15.4(3)S3' ||
ver == '15.4(1)S4' ||
ver == '15.4(2)S3' ||
ver == '15.4(2)S4' ||
ver == '15.4(3)S4' ||
ver == '15.4(3)S5' ||
ver == '15.4(3)S6' ||
ver == '15.4(3)S7' ||
ver == '15.4(3)S6a' ||
ver == '15.4(3)S8' ||
ver == '15.2(2)SNI' ||
ver == '15.0(2)EZ' ||
ver == '15.2(1)EY' ||
ver == '15.0(2)EJ' ||
ver == '15.0(2)EJ1' ||
ver == '15.0(2)EH' ||
ver == '15.2(5)EX' ||
ver == '15.0(2)EK' ||
ver == '15.0(2)EK1' ||
ver == '15.5(1)S' ||
ver == '15.5(2)S' ||
ver == '15.5(1)S1' ||
ver == '15.5(3)S' ||
ver == '15.5(1)S2' ||
ver == '15.5(1)S3' ||
ver == '15.5(2)S1' ||
ver == '15.5(2)S2' ||
ver == '15.5(3)S1' ||
ver == '15.5(3)S1a' ||
ver == '15.5(2)S3' ||
ver == '15.5(3)S2' ||
ver == '15.5(3)S0a' ||
ver == '15.5(3)S3' ||
ver == '15.5(1)S4' ||
ver == '15.5(2)S4' ||
ver == '15.5(3)S4' ||
ver == '15.5(3)S5' ||
ver == '15.5(3)S6' ||
ver == '15.5(3)S6a' ||
ver == '15.5(3)S6b' ||
ver == '15.1(3)SVG' ||
ver == '15.2(2)EB' ||
ver == '15.2(2)EB1' ||
ver == '15.2(2)EB2' ||
ver == '15.5(3)SN' ||
ver == '15.0(2)SQD' ||
ver == '15.0(2)SQD1' ||
ver == '15.0(2)SQD2' ||
ver == '15.0(2)SQD3' ||
ver == '15.0(2)SQD4' ||
ver == '15.0(2)SQD5' ||
ver == '15.0(2)SQD6' ||
ver == '15.0(2)SQD7' ||
ver == '15.6(1)S' ||
ver == '15.6(2)S' ||
ver == '15.6(2)S1' ||
ver == '15.6(1)S1' ||
ver == '15.6(1)S2' ||
ver == '15.6(2)S0a' ||
ver == '15.6(2)S2' ||
ver == '15.6(1)S3' ||
ver == '15.6(2)S3' ||
ver == '15.6(1)S4' ||
ver == '15.6(2)S4' ||
ver == '15.6(2)SP' ||
ver == '15.6(2)SP1' ||
ver == '15.6(2)SP2' ||
ver == '15.6(2)SP3' ||
ver == '15.6(2)SP3b' ||
ver == '15.6(2)SN' ||
ver == '15.1(3)SVJ2' ||
ver == '15.2(4)EC1' ||
ver == '15.2(4)EC2'
) flag++;

cmds = make_list();
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | include ip helper-address", "show running-config | include ip helper-address");
  if (check_cisco_result(buf))
  {
    if (preg(string:buf, pattern:"ip helper-address", multiline:TRUE))
    {
      cmds = make_list(cmds, "show running-config | include ip helper-address");
      buf2 =  cisco_command_kb_item("Host/Cisco/Config/show running-config | include ip dhcp relay information option", "show running-config | include ip dhcp relay information option");
      if (check_cisco_result(buf2))
      {
        if (preg(multiline:TRUE, pattern:"ip dhcp relay information option", string:buf2))
        {
          cmds = make_list(cmds,"show running-config | include ip dhcp relay information option");
          flag = 1;
        }
      }
    }
  }
  else if (cisco_needs_enable(buf))
    override = 1;

  if (!flag && !override) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS", ver);
}

if (flag || override)
{
  security_report_cisco(
    port     : port,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : "CSCvg62730, CSCvg62754, CSCuh91645",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
