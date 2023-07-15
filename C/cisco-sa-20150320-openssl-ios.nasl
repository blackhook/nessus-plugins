#TRUSTED 50c5ee3159f76d52106959d5fccc37925a0fdfdd11fa504dc19da1d5d480717579569a2685cc828db889bf51b0b57b5541658aeda2afcdf859221a79f8d5ca2e7793ea33022e59ab5a5824cae5520e404875efa5f364df071088d3b6ec9c3ac4d5814e0eeb22a41a1896fa743410f3f7950153b9562d172988e98f943289066679f84abb29aeaaafa2c6ddfe6b9c6bf5045189f628b845eb5aeb2581b601d4cce8ddbc181092198ad4d1fa8a4f94cccf5e470b3f927f44c833322123433f12e853e7384cb2fc8a5c8a6ff7a5efa4c40c0bcbe060a95ae1417c8cbaa1f5234ce03acdfb09b4312c1f57c794a0c56bc055a37b6651a8bb47350981757ab20d4b1d62608612ec4f5043b25ddf5fca655bded1a1da0383a9d8a2c10506d42f7f2b70999c6435911c477eeffb76c2ff212b2ffda5ff87abf21a42074aab62db323f04cd10403706fb54428943cdf59564667f08aea8eb40993d6cc28d67eed99e74c01a6a3573bf5b0df67603109fcb97a9bf3e970a2611b74da82ba57d4e3d0d5caa7d251abae80952a0bbb938c4b8f1f1057c9dc530d1bb967030a1c22e88f3ef7e62d13fb20d90e1d01fccda0aa11ff43fab2ca1920830c6a81072ad92a565a72e361c07f448312e3998a7e2c84ccb12ff546121c91be8094ad336320beb71e0edceb8363e3ec7e458ee01fc87bdee006d6945a50acbdd1a8a88af725d0b9c0acb
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90525);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/19");

  script_cve_id(
    "CVE-2015-0209",
    "CVE-2015-0286",
    "CVE-2015-0287",
    "CVE-2015-0288",
    "CVE-2015-0289",
    "CVE-2015-0292",
    "CVE-2015-0293"
  );
  script_bugtraq_id(
    73225,
    73227,
    73228,
    73231,
    73232,
    73237,
    73239
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCut46130");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150320-openssl");

  script_name(english:"Cisco IOS Multiple OpenSSL Vulnerabilities (CSCut46130)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS device is missing a vendor-supplied security
patch and has an IOS service configured to use TLS or SSL. It is,
therefore, affected by the following vulnerabilities in the bundled
OpenSSL library :

  - A use-after-free condition exists in the
    d2i_ECPrivateKey() function due to improper processing
    of malformed EC private key files during import. A
    remote attacker can exploit this to dereference or free
    already freed memory, resulting in a denial of service
    or other unspecified impact. (CVE-2015-0209)

  - An invalid read error exists in the ASN1_TYPE_cmp()
    function due to improperly performed boolean-type
    comparisons. A remote attacker can exploit this, via a
    crafted X.509 certificate to an endpoint that uses the
    certificate-verification feature, to cause an invalid
    read operation, resulting in a denial of service.
    (CVE-2015-0286)

  - A flaw exists in the ASN1_item_ex_d2i() function due to
    a failure to reinitialize 'CHOICE' and 'ADB' data
    structures when reusing a structure in ASN.1 parsing.
    This allows a remote attacker to cause an invalid write
    operation and memory corruption, resulting in a denial
    of service. (CVE-2015-0287)

  - A NULL pointer dereference flaw exists in the
    X509_to_X509_REQ() function due to improper processing
    of certificate keys. This allows a remote attacker, via
    a crafted X.509 certificate, to cause a denial of
    service. (CVE-2015-0288)

  - A NULL pointer dereference flaw exists in the PKCS#7
    parsing code due to incorrect handling of missing outer
    ContentInfo. This allows a remote attacker, using an
    application that processes arbitrary PKCS#7 data and
    providing malformed data with ASN.1 encoding, to cause
    a denial of service. (CVE-2015-0289)

  - An integer underflow condition exists in the
    EVP_DecodeUpdate() function due to improper validation
    of base64 encoded input when decoding. This allows a
    remote attacker, using maliciously crafted base64 data,
    to cause a segmentation fault or memory corruption,
    resulting in a denial of service or possibly the
    execution of arbitrary code. (CVE-2015-0292)

  - A flaw exists in servers that both support SSLv2 and
    enable export cipher suites due to improper
    implementation of SSLv2. A remote attacker can exploit
    this, via a crafted CLIENT-MASTER-KEY message, to cause
    a denial of service. (CVE-2015-0293)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150320-openssl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2beef118");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCut46130");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150319.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCut46130.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

##
# Examines the output of show running config all for known SSL
# utilizing IOS features.
#
# @remark 'override' in the return value signals that the scan
#         was not provided sufficient credentials to check for
#         the related configurations. 'flag' signals whether or
#         not the configuration examined appears to be using SSL
#
# @return always an array like:
# {
#   'override' : (TRUE|FALSE),
#   'flag'     : (TRUE|FALSE)
# }
##
function ios_using_openssl()
{
  local_var res, buf;
  res = make_array(
    'override',  TRUE,
    'flag',      TRUE
  );

  # Signal we need local checks
  if (!get_kb_item("Host/local_checks_enabled"))
    return res;

  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_running-config_all",
    "show running-config all"
  );

  # Privilege escalation required
  if (cisco_needs_enable(buf))
    return res;

  res['flag'] = FALSE;

  # Check to make sure no errors in command output
  if(!check_cisco_result(buf))
    return res;

  # All good check for various SSL services
  res['override'] = FALSE;

   # Web UI HTTPS
  if (preg(string:buf, pattern:"^ip http secure-server", multiline:TRUE))
    res['flag'] = TRUE;
  # HTTPS client feature / Voice-XML HTTPS client
  else if (preg(string:buf, pattern:"^(ip )?http client secure-", multiline:TRUE))
    res['flag'] = TRUE;
  # CNS feature
  else if (preg(string:buf, pattern:"^cns (config|exec|event) .* encrypt", multiline:TRUE))
    res['flag'] = TRUE;
  # CMTS billing feature
  else if (preg(string:buf, pattern:"^cable metering .* secure", multiline:TRUE))
    res['flag'] = TRUE;
  # SSL VPN
  else if (
    cisco_check_sections(
      config        : buf,
      section_regex : "^webvpn gateway ",
      config_regex  :'^\\s*inservice'
     )
  ) res['flag'] = TRUE;
  # Settlement for Packet Telephony feature
  else if (
    cisco_check_sections(
      config        : buf,
      section_regex : "^settlement ",
      config_regex  : make_list('^\\s*url https:', '^\\s*no shutdown')
    )
  ) res['flag'] = TRUE;

  return res;
}

##
# Main check logic
##

# Look for known affected versions
affected = make_list(
'12.2(58)EX',    '12.2(58)EY',    '12.2(58)EY1',   '12.2(58)EY2',   '12.2(58)EZ',    '12.2(60)EZ',    '12.2(60)EZ1',
'12.2(60)EZ2',   '12.2(60)EZ3',   '12.2(60)EZ4',   '12.2(60)EZ5',   '12.2(60)EZ6',   '12.2(60)EZ7',   '12.2(60)EZ8',
'12.2(58)SE',    '12.2(58)SE1',   '12.2(58)SE2',   '12.2(54)SG',    '12.2(54)SG1',   '12.2(54)WO',    '12.2(54)XO',
'12.4(22)GC1',   '12.4(24)GC1',   '12.4(24)GC3',   '12.4(24)GC3a',  '12.4(24)GC4',   '12.4(24)GC5',   '12.4(22)MD',
'12.4(22)MD1',   '12.4(22)MD2',   '12.4(24)MD',    '12.4(24)MD1',   '12.4(24)MD2',   '12.4(24)MD3',   '12.4(24)MD4',
'12.4(24)MD5',   '12.4(24)MD6',   '12.4(24)MD7',   '12.4(22)MDA',   '12.4(22)MDA1',  '12.4(22)MDA2',  '12.4(22)MDA3',
'12.4(22)MDA4',  '12.4(22)MDA5',  '12.4(22)MDA6',  '12.4(24)MDA1',  '12.4(24)MDA10', '12.4(24)MDA11', '12.4(24)MDA12',
'12.4(24)MDA13', '12.4(24)MDA2',  '12.4(24)MDA3',  '12.4(24)MDA4',  '12.4(24)MDA5',  '12.4(24)MDA6',  '12.4(24)MDA7',
'12.4(24)MDA8',  '12.4(24)MDA9',  '12.4(24)MDB',   '12.4(24)MDB1',  '12.4(24)MDB10', '12.4(24)MDB11', '12.4(24)MDB12',
'12.4(24)MDB13', '12.4(24)MDB14', '12.4(24)MDB15', '12.4(24)MDB16', '12.4(24)MDB17', '12.4(24)MDB18', '12.4(24)MDB19',
'12.4(24)MDB3',  '12.4(24)MDB4',  '12.4(24)MDB5',  '12.4(24)MDB5a', '12.4(24)MDB6',  '12.4(24)MDB7',  '12.4(24)MDB8',
'12.4(24)MDB9',  '12.4(22)T',     '12.4(22)T1',    '12.4(22)T2',    '12.4(22)T3',    '12.4(22)T4',    '12.4(22)T5',
'12.4(24)T',     '12.4(24)T1',    '12.4(24)T2',    '12.4(24)T3',    '12.4(24)T3e',   '12.4(24)T3f',   '12.4(24)T4',
'12.4(24)T4a',   '12.4(24)T4b',   '12.4(24)T4c',   '12.4(24)T4d',   '12.4(24)T4e',   '12.4(24)T4f',   '12.4(24)T4l',
'12.4(24)T5',    '12.4(24)T6',    '12.4(24)T7',    '12.4(24)T8',    '12.4(22)XR1',   '12.4(22)XR10',  '12.4(22)XR11',
'12.4(22)XR12',  '12.4(22)XR2',   '12.4(22)XR3',   '12.4(22)XR4',   '12.4(22)XR5',   '12.4(22)XR6',   '12.4(22)XR7',
'12.4(22)XR8',   '12.4(22)XR9',   '12.4(22)YD',    '12.4(22)YD1',   '12.4(22)YD2',   '12.4(22)YD3',   '12.4(22)YD4',
'12.4(22)YE2',   '12.4(22)YE3',   '12.4(22)YE4',   '12.4(22)YE5',   '12.4(22)YE6',   '12.4(24)YE',    '12.4(24)YE1',
'12.4(24)YE2',   '12.4(24)YE3',   '12.4(24)YE3a',  '12.4(24)YE3b',  '12.4(24)YE3c',  '12.4(24)YE3d',  '12.4(24)YE3e',
'12.4(24)YE4',   '12.4(24)YE5',   '12.4(24)YE6',   '12.4(24)YE7',   '12.4(24)YG1',   '12.4(24)YG2',   '12.4(24)YG3',
'12.4(24)YG4',   '15.0(2)EB',     '15.0(2)EC',     '15.0(2)ED',     '15.0(2)ED1',    '15.0(2)EH',     '15.0(2)EJ',
'15.0(2)EJ1',    '15.0(2)EK',     '15.0(2)EK1',    '15.0(1)EX',     '15.0(2)EX',     '15.0(2)EX1',    '15.0(2)EX2',
'15.0(2)EX3',    '15.0(2)EX4',    '15.0(2)EX5',    '15.0(2)EX8',    '15.0(2a)EX5',   '15.0(1)EY',     '15.0(1)EY1',
'15.0(1)EY2',    '15.0(2)EY',     '15.0(2)EY1',    '15.0(2)EY2',    '15.0(2)EY3',    '15.0(2)EZ',     '15.0(1)M',
'15.0(1)M1',     '15.0(1)M10',    '15.0(1)M2',     '15.0(1)M3',     '15.0(1)M4',     '15.0(1)M5',     '15.0(1)M6',
'15.0(1)M7',     '15.0(1)M8',     '15.0(1)M9',     '15.0(1)MR',     '15.0(2)MR',     '15.0(1)S2',     '15.0(1)S5',
'15.0(1)S6',     '15.0(1)SE',     '15.0(1)SE1',    '15.0(1)SE2',    '15.0(1)SE3',    '15.0(2)SE',     '15.0(2)SE1',
'15.0(2)SE2',    '15.0(2)SE3',    '15.0(2)SE4',    '15.0(2)SE5',    '15.0(2)SE6',    '15.0(2)SE7',    '15.0(2)SG',
'15.0(2)SG1',    '15.0(2)SG10',   '15.0(2)SG2',    '15.0(2)SG3',    '15.0(2)SG4',    '15.0(2)SG5',    '15.0(2)SG6',
'15.0(2)SG7',    '15.0(2)SG8',    '15.0(2)SQD',    '15.0(2)SQD1',   '15.0(1)XA',     '15.0(1)XA1',    '15.0(1)XA2',
'15.0(1)XA3',    '15.0(1)XA4',    '15.0(1)XA5',    '15.0(1)XO',     '15.0(1)XO1',    '15.0(2)XO',     '15.1(2)EY',
'15.1(2)EY1a',   '15.1(2)EY2',    '15.1(2)EY2a',   '15.1(2)EY3',    '15.1(2)EY4',    '15.1(2)GC',     '15.1(2)GC1',
'15.1(2)GC2',    '15.1(4)GC',     '15.1(4)GC1',    '15.1(4)GC2',    '15.1(4)M',      '15.1(4)M1',     '15.1(4)M10',
'15.1(4)M2',     '15.1(4)M3',     '15.1(4)M3a',    '15.1(4)M4',     '15.1(4)M5',     '15.1(4)M6',     '15.1(4)M7',
'15.1(4)M8',     '15.1(4)M9',     '15.1(1)MR',     '15.1(1)MR1',    '15.1(1)MR2',    '15.1(1)MR3',    '15.1(1)MR4',
'15.1(3)MR',     '15.1(3)MRA',    '15.1(3)MRA1',   '15.1(3)MRA2',   '15.1(3)MRA3',   '15.1(3)MRA4',   '15.1(1)S',
'15.1(1)S1',     '15.1(1)S2',     '15.1(2)S',      '15.1(2)S1',     '15.1(2)S2',     '15.1(3)S',      '15.1(3)S0a',
'15.1(3)S1',     '15.1(3)S2',     '15.1(3)S3',     '15.1(3)S4',     '15.1(3)S5',     '15.1(3)S5a',    '15.1(3)S6',
'15.1(1)SG',     '15.1(1)SG1',    '15.1(1)SG2',    '15.1(2)SG',     '15.1(2)SG1',    '15.1(2)SG2',    '15.1(2)SG3',
'15.1(2)SG4',    '15.1(2)SG5',    '15.1(2)SG6',    '15.1(2)SNG',    '15.1(2)SNH',    '15.1(2)SNI',    '15.1(2)SNI1',
'15.1(3)SVB1',   '15.1(3)SVD',    '15.1(3)SVD1',   '15.1(3)SVD2',   '15.1(3)SVE',    '15.1(3)SVF',    '15.1(3)SVF1',
'15.1(3)SVF4a',  '15.1(1)SY',     '15.1(1)SY1',    '15.1(1)SY2',    '15.1(1)SY3',    '15.1(1)SY4',    '15.1(1)SY5',
'15.1(2)SY',     '15.1(2)SY1',    '15.1(2)SY2',    '15.1(2)SY3',    '15.1(2)SY4',    '15.1(2)SY4a',   '15.1(2)SY5',
'15.1(1)T',      '15.1(1)T1',     '15.1(1)T2',     '15.1(1)T3',     '15.1(1)T4',     '15.1(1)T5',     '15.1(2)T',
'15.1(2)T0a',    '15.1(2)T1',     '15.1(2)T2',     '15.1(2)T2a',    '15.1(2)T3',     '15.1(2)T4',     '15.1(2)T5',
'15.1(3)T',      '15.1(3)T1',     '15.1(3)T2',     '15.1(3)T3',     '15.1(3)T4',     '15.1(1)XB',     '15.2(1)E',
'15.2(1)E1',     '15.2(1)E2',     '15.2(1)E3',     '15.2(2)E',      '15.2(2)E1',     '15.2(2)E2',     '15.2(2a)E1',
'15.2(3)E',      '15.2(3)E1',     '15.2(3)E2',     '15.2(3a)E',     '15.2(2)EB',     '15.2(2)EB1',    '15.2(1)EY',
'15.2(2)EA1',    '15.2(2)EA2',    '15.2(3)EA',     '15.2(1)GC',     '15.2(1)GC1',    '15.2(1)GC2',    '15.2(2)GC',
'15.2(3)GC',     '15.2(3)GC1',    '15.2(4)GC',     '15.2(4)GC1',    '15.2(4)GC2',    '15.2(4)GC3',    '15.2(2)JA',
'15.2(2)JA1',    '15.2(4)JA',     '15.2(4)JA1',    '15.2(2)JAX',    '15.2(2)JAX1',   '15.2(2)JB',     '15.2(2)JB1',
'15.2(2)JB2',    '15.2(2)JB3',    '15.2(2)JB4',    '15.2(2)JB5',    '15.2(4)JB',     '15.2(4)JB1',    '15.2(4)JB2',
'15.2(4)JB3',    '15.2(4)JB3a',   '15.2(4)JB3b',   '15.2(4)JB3h',   '15.2(4)JB3s',   '15.2(4)JB4',    '15.2(4)JB5',
'15.2(4)JB5h',   '15.2(4)JB5m',   '15.2(4)JB50',   '15.2(4)JB6',    '15.2(4)JB7',    '15.2(2)JN1',    '15.2(2)JN2',
'15.2(4)JN',     '15.2(4)M',      '15.2(4)M1',     '15.2(4)M2',     '15.2(4)M3',     '15.2(4)M4',     '15.2(4)M5',
'15.2(4)M6',     '15.2(4)M6a',    '15.2(4)M7',     '15.2(4)M8',     '15.2(1)S',      '15.2(1)S1',     '15.2(1)S2',
'15.2(2)S',      '15.2(2)S0a',    '15.2(2)S0c',    '15.2(2)S1',     '15.2(2)S2',     '15.2(4)S',      '15.2(4)S1',
'15.2(4)S2',     '15.2(4)S3',     '15.2(4)S3a',    '15.2(4)S4',     '15.2(4)S4a',    '15.2(4)S5',     '15.2(4)S6',
'15.2(4)S7',     '15.2(2)SNG',    '15.2(2)SNH1',   '15.2(2)SNI',    '15.2(1)SY',     '15.2(1)SY0a',   '15.2(1)SY1',
'15.2(1)T',      '15.2(1)T1',     '15.2(1)T2',     '15.2(1)T3',     '15.2(1)T3a',    '15.2(1)T4',     '15.2(2)T',
'15.2(2)T1',     '15.2(2)T2',     '15.2(2)T3',     '15.2(2)T4',     '15.2(3)T',      '15.2(3)T1',     '15.2(3)T2',
'15.2(3)T3',     '15.2(3)T4',     '15.3(3)JA',     '15.3(3)JA1',    '15.3(3)JA1m',   '15.3(3)JA1n',   '15.3(3)JA4',
'15.3(3)JA77',   '15.3(3)JAA',    '15.3(3)JAB',    '15.3(3)JAX',    '15.3(3)JAX1',   '15.3(3)JAX2',   '15.3(3)JBB',
'15.3(3)JN1',    '15.3(3)JN2',    '15.3(3)JN3',    '15.3(3)JN4',    '15.3(3)JNB',    '15.3(3)JNB1',   '15.3(3)JNB2',
'15.3(3)M',      '15.3(3)M1',     '15.3(3)M2',     '15.3(3)M3',     '15.3(3)M4',     '15.3(3)M5',     '15.3(1)S',
'15.3(1)S1',     '15.3(1)S2',     '15.3(2)S',      '15.3(2)S0a',    '15.3(2)S1',     '15.3(2)S2',     '15.3(3)S',
'15.3(3)S1',     '15.3(3)S1a',    '15.3(3)S2',     '15.3(3)S3',     '15.3(3)S4',     '15.3(3)S5',     '15.3(3)S6',
'15.3(1)T',      '15.3(1)T1',     '15.3(1)T2',     '15.3(1)T3',     '15.3(1)T4',     '15.3(2)T',      '15.3(2)T1',
'15.3(2)T2',     '15.3(2)T3',     '15.3(2)T4',     '15.4(1)CG',     '15.4(1)CG1',    '15.4(2)CG',     '15.4(3)M',
'15.4(3)M1',     '15.4(3)M2',     '15.4(3)M3',     '15.4(1)S',      '15.4(1)S1',     '15.4(1)S2',     '15.4(1)S3',
'15.4(1)S4',     '15.4(2)S',      '15.4(2)S1',     '15.4(2)S2',     '15.4(2)S3',     '15.4(3)S',      '15.4(3)S1',
'15.4(3)S2',     '15.4(3)S3',     '15.4(1)T',      '15.4(1)T1',     '15.4(1)T2',     '15.4(1)T3',     '15.4(1)T4',
'15.4(2)T',      '15.4(2)T1',     '15.4(2)T2',     '15.4(2)T3',     '15.5(1)S',      '15.5(1)S1',     '15.5(1)S2',
'15.5(2)S',      '15.5(1)T',      '15.5(1)T1',     '15.5(1)T2',     '15.5(2)T'
);

flag = FALSE;
foreach afver (affected)
{
  if (ver == afver)
  {
    flag = TRUE;
    break;
  }
}

if (!flag)
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS", ver);

# Configuration check
sslcheck = ios_using_openssl();

if (!sslcheck['flag'] && !sslcheck['override'])
  audit(AUDIT_HOST_NOT, "affected because it does not appear as though any service utilizing the OpenSSL library is enabled");

# Override is shown regardless of verbosity
report = "";
if (report_verbosity > 0)
{
  order  = make_list('Cisco bug ID', 'Installed release');
  report = make_array(
    order[0], 'CSCut46130',
    order[1], ver
  );
  report = report_items_str(report_items:report, ordered_fields:order);
}

security_hole(port:0, extra:report+cisco_caveat(sslcheck['override']));
