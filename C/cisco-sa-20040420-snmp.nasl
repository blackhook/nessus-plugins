#TRUSTED 6c2ef748280b708d452bbadfbf17d94b4b7fdced8aeb682b10585c8fb7c48be4e26fb798d5e6e1122da4270f6fbb3049e35d55c55a1fa7ddca3becd10db5f9b1e18a68c0cc91067382293589ccd4589312900338b3df076b07ae0533869670437c6f0ed00e31dbbd06d5bedf7b96adbf8350c26140a4cccf5ac153c9e23a07dedfab925809a2e5f2a55ddc5df6ea0dd06458421f0146cd783b585f154a28e2f15369e160f344a312834dbc1ba9cee716e7218318b80d1c1b9853623dd523af3900b79e7ed86cd621ea7f48e0f861a5642f927820069bd0e7395620928270936b92851be4cecab1487d5da6917888385cf795123c461a02295f3b82d07466193e36c825fe12c31bd80933e857fc70d6d30625ad72d0616fc888e8b10fc952472430a1288de6e18aaf1fb68e0dae301d8be38b118f4650c37e3da2aacbebbdb77848a7eed3b230c9bed7b48e726cb74a2a0fc3eb7fc746ef92da1e53d6ee2762b5de38b162a8047c5d5133340c7704101730be5d85b8f50a9e5e11747a3e7d482ac3fef4f7e167bee05d8c79c6e7dcaf56f636b276f0c5090f847f1c7f2b3bd8131ff0bc9eedb248281084e56f722e01fabb5f71f4d31188c4d8adec47d902fe33905a363e6b12c179608ea23fc6b41977e79f49962a2420e3a776110a7ecbeb7a2bc9b098c9998acf90a622b26fe56a77c10042e0d7d1c1ff7bcb28b6c7138212
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a008021b9b5.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48974);
 script_version("1.21");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2004-0714");
 script_bugtraq_id(10186);
 script_xref(name:"CERT", value:"162451");
 script_xref(name:"CISCO-BUG-ID", value:"CSCeb22276");
 script_xref(name:"CISCO-BUG-ID", value:"CSCed68575");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20040420-snmp");
 script_name(english:"Vulnerabilities in SNMP Message Processing - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Cisco Internetwork Operating System (IOS) Software release trains
12.0S, 12.1E, 12.2, 12.2S, 12.3, 12.3B and 12.3T may contain a
vulnerability in processing SNMP requests which, if exploited, could
cause the device to reload.
 The vulnerability is only present in certain IOS releases on Cisco
routers and switches. This behavior was introduced via a code change
and is resolved with CSCed68575.
 This vulnerability can be remotely triggered. A successful
exploitation of this vulnerability may cause a reload of the device and
could be exploited repeatedly to produce a denial of service (DoS).
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b858efa");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a008021b9b5.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?c244c7af");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20040420-snmp.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/20");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/04/20");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2018 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

if (version == '12.3(4)XG') flag++;
else if (version == '12.3(2)XF') flag++;
else if (version == '12.3(2)XE') flag++;
else if (version == '12.3(4)XD1') flag++;
else if (version == '12.3(4)XD') flag++;
else if (version == '12.3(2)XC2') flag++;
else if (version == '12.3(2)XC1') flag++;
else if (version == '12.3(4)T3') flag++;
else if (version == '12.3(4)T2a') flag++;
else if (version == '12.3(4)T2') flag++;
else if (version == '12.3(4)T1') flag++;
else if (version == '12.3(4)T') flag++;
else if (version == '12.3(5a)B') flag++;
else if (version == '12.3(6)') flag++;
else if (version == '12.3(5b)') flag++;
else if (version == '12.3(5a)') flag++;
else if (version == '12.3(5)') flag++;
else if (version == '12.2(23)SW1') flag++;
else if (version == '12.2(23)SW') flag++;
else if (version == '12.2(21)SW1') flag++;
else if (version == '12.2(21)SW') flag++;
else if (version == '12.2(20)SW') flag++;
else if (version == '12.2(20)S1') flag++;
else if (version == '12.2(20)S') flag++;
else if (version == '12.2(12h)M1') flag++;
else if (version == '12.2(23)') flag++;
else if (version == '12.2(21a)') flag++;
else if (version == '12.2(21)') flag++;
else if (version == '12.2(12h)') flag++;
else if (version == '12.2(12g)') flag++;
else if (version == '12.1(20)EW1') flag++;
else if (version == '12.1(20)EW') flag++;
else if (version == '12.1(20)EU') flag++;
else if (version == '12.1(20)EO') flag++;
else if (version == '12.1(20)EC1') flag++;
else if (version == '12.1(20)EC') flag++;
else if (version == '12.1(20)EB') flag++;
else if (version == '12.1(20)EA1') flag++;
else if (version == '12.1(20)E2') flag++;
else if (version == '12.1(20)E1') flag++;
else if (version == '12.1(20)E') flag++;
else if (version == '12.0(27)S') flag++;
else if (version == '12.0(26)S1') flag++;
else if (version == '12.0(24)S5') flag++;
else if (version == '12.0(24)S4a') flag++;
else if (version == '12.0(24)S4') flag++;
else if (version == '12.0(23)S5') flag++;
else if (version == '12.0(23)S4') flag++;


if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"snmp-server\s+enable", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
