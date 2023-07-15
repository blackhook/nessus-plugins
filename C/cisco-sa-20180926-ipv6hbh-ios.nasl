#TRUSTED 7ae9f6d0558ce6d16899b2a2e5e2f3e8bd84b5da448a01a694af95addde94f90200fcf378c33ce5e3527108974d88bed0a51f714770794ea9cc895ec43cf9551ad3147be9771ad90bbb0b3aea7d9d6b3af72ef0e21851ac9b9e2c1fdc3434d117913803c9777c380e118957b5c89569799eb5e356bc8a57277e834781f813b6963c83ff9e7e62b6a42eedae77f31f5e2221b75e4b9adb0fae3a76d2bd46e10fc213fcbf0795fede756b13cd737e3e6533435c986420f5a304299f759237bbdda9707f8136a35b6f236c4935fc5fbc56e16d929410ed6c6f1c85166377a2d6aae033cb9be879983998c31d7978d8e258b319c78914899c978f7f4453c4cf5a9c08b46e7d08bc944dcecc9ef4e42062d62f46167e000ba53a8ff306af56ba8b6b3663ac23f57f35eba80c8d8f57067370da484fff6faec38255f4fb0d1478463c6320d82d9cadb5a5d497f53f035fa1b279df65bc4e16c181c34c2b332cc99d424ee55a54b10e01c4723f37418771b121bb8502f99e8f80b61586b87c8bdd66906be32c545478a35ee62eac30d1ed97ae7ad7ef78126fee646ae4776f17cec339c9983c5c1e97408dd42079207ab2a85f57a1e5e968327d8300d8c8fc438a45e671e3e7d96b0b81204da88b0ad51da073bfee15636d3a796bf34eae8040a3ceee7d7d90bb00fa201a88fcc2f10bfbb48a28b4f6c48d5c69205a516bb906857ef3e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(117949);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2018-0467");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz28570");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-ipv6hbh");
  script_xref(name:"IAVA", value:"2018-A-0312-S");

  script_name(english:"Cisco IOS Software IPv6 Hop-by-Hop DoS Vulnerability (cisco-sa-20180926-ipv6hbh)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-ipv6hbh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d5b700b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz28570");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCuz28570.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0467");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS");

version_list = make_list(
  "15.3(3)S",
  "15.3(3)S1",
  "15.3(3)S2",
  "15.3(3)S3",
  "15.3(3)S6",
  "15.3(3)S4",
  "15.3(3)S1a",
  "15.3(3)S5",
  "15.3(3)S7",
  "15.3(3)S8",
  "15.3(3)S9",
  "15.3(3)S8a",
  "15.2(3)E",
  "15.2(4)E",
  "15.2(3)E1",
  "15.2(3)E2",
  "15.2(3a)E",
  "15.2(3)E3",
  "15.2(4)E1",
  "15.2(4)E2",
  "15.2(4m)E1",
  "15.2(3)E4",
  "15.2(5)E",
  "15.2(4)E3",
  "15.2(5)E1",
  "15.2(5b)E",
  "15.2(4m)E3",
  "15.2(3)E5",
  "15.2(4n)E2",
  "15.2(4o)E2",
  "15.2(4)E4",
  "15.2(5)E2",
  "15.2(4p)E1",
  "15.2(5)E2b",
  "15.2(4m)E2",
  "15.2(4o)E3",
  "15.2(4q)E1",
  "15.2(4s)E1",
  "15.4(2)S",
  "15.4(3)S",
  "15.4(2)S1",
  "15.4(3)S1",
  "15.4(2)S2",
  "15.4(3)S2",
  "15.4(3)S3",
  "15.4(2)S3",
  "15.4(2)S4",
  "15.4(3)S4",
  "15.4(3)S5",
  "15.4(3)S6",
  "15.4(3)S7",
  "15.4(3)S6a",
  "15.5(1)S",
  "15.5(2)S",
  "15.5(1)S1",
  "15.5(3)S",
  "15.5(1)S2",
  "15.5(1)S3",
  "15.5(2)S1",
  "15.5(2)S2",
  "15.5(3)S1a",
  "15.5(2)S3",
  "15.5(3)S2",
  "15.5(3)S3",
  "15.5(1)S4",
  "15.5(2)S4",
  "15.5(3)S4",
  "15.5(3)S5",
  "15.2(3)EA",
  "15.2(4)EA",
  "15.2(4)EA1",
  "15.2(5)EA",
  "15.2(4)EA5",
  "15.4(2)SN",
  "15.4(2)SN1",
  "15.4(3)SN1",
  "15.4(3)SN1a",
  "15.5(3)M",
  "15.5(3)M1",
  "15.5(3)M2",
  "15.5(3)M2a",
  "15.5(3)M3",
  "15.5(3)M4",
  "15.5(3)M4a",
  "15.5(3)M5",
  "15.5(3)M4b",
  "15.5(3)M4c",
  "15.5(3)M5a",
  "15.5(1)SN",
  "15.5(1)SN1",
  "15.5(2)SN",
  "15.5(3)SN0a",
  "15.5(3)SN",
  "15.6(1)S",
  "15.6(2)S",
  "15.6(2)S1",
  "15.6(1)S1",
  "15.6(1)S2",
  "15.6(2)S2",
  "15.6(1)S3",
  "15.6(2)S3",
  "15.6(1)T",
  "15.6(2)T",
  "15.6(1)T0a",
  "15.6(1)T1",
  "15.6(2)T1",
  "15.6(1)T2",
  "15.6(2)T2",
  "15.6(1)T3",
  "15.6(2)SP",
  "15.6(2)SP1",
  "15.6(2)SP2",
  "15.6(2)SP3b",
  "15.6(1)SN",
  "15.6(1)SN1",
  "15.6(2)SN",
  "15.6(1)SN2",
  "15.6(1)SN3",
  "15.6(3)SN",
  "15.6(4)SN",
  "15.6(5)SN",
  "15.6(6)SN",
  "15.6(3)M",
  "15.6(3)M1",
  "15.6(3)M0a",
  "15.6(3)M1a",
  "15.6(3)M2",
  "15.6(3)M2a",
  "15.1(3)SVK4b"
  );

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ipv6_enabled'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCuz28570",
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
