#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111666);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-5924", "CVE-2018-5925");
  script_bugtraq_id(105010);
  script_xref(name:"IAVA", value:"2018-A-0252");

  script_name(english:"HP Ink Printers Multiple Vulnerabilities (HPSBHF03589)");
  script_summary(english:"Checks the firmware version of HP printers.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The firmware version running on the remote host is vulnerable to
multiple vulnerabilities. An unauthenticated remote attacker could
gain system-level unauthorized access to the affected device.

Note that Nessus has not tested for these issues but has instead
relied only on the self-reported version number of the device.");
  script_set_attribute(attribute:"see_also", value:"https://research.checkpoint.com/sending-fax-back-to-the-dark-ages/");
  script_set_attribute(attribute:"see_also", value:"https://support.hp.com/us-en/document/c06097712");
  script_set_attribute(attribute:"solution", value:
"Upgrade the host firmware to the version provided by the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5925");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:hp:printers");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_www_detect.nbin");
  script_require_keys("installed_sw/Embedded HP Server");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("vcf.inc");

function buildpatches()
{
  local_var patches, list, mod;

  patches = {};

  list = make_list(
    "J6U57B",
    "J9V82A",
    "J9V82B",
    "J9V82C",
    "J9V82D",
    "J6U55A",
    "J6U55B",
    "J6U55C",
    "J6U55D",
    "J9V80A",
    "J9V80B",
    "D3Q15A",
    "D3Q15B",
    "D3Q15D",
    "D3Q17A",
    "D3Q17C",
    "D3Q17D",
    "D3Q19A",
    "D3Q19D",
    "D3Q20A",
    "D3Q20B",
    "D3Q20C",
    "D3Q20D",
    "D3Q21A",
    "D3Q21C",
    "D3Q21D",
    "K9Z76A",
    "K9Z76D",
    "D3Q16A",
    "D3Q16B",
    "D3Q16C",
    "D3Q16D"
  );
  foreach mod (list)
  {
    patches[mod] = "1829A";
  }

  list = make_list(
    "Y3Z57",
    "W1B33",
    "W1B39",
    "W1B37",
    "W1B38",
    "Y3Z45",
    "Y3Z47",
    "Y3Z46",
    "Y3Z44",
    "W1B31",
    "Y3Z54"
  );
  foreach mod (list)
  {
    patches[mod] = "1828A";
  }

  list = make_list(
    "CN459A",
    "CN463A",
    "CN460A",
    "CN461A",
    "CV037A",
    "CN598A",
    "CQ891A",
    "CQ891B",
    "CQ891C",
    "CQ891AR",
    "CQ890A",
    "CQ890B",
    "CQ890C",
    "CQ890D",
    "CQ890E",
    "CQ890AR",
    "CQ893A",
    "CQ893B",
    "CQ893C",
    "CQ893E",
    "CQ893AR",
    "CQ183[A-C]",
    "CQ76[1-4][A-C]"
  );
  foreach mod (list)
  {
    patches[mod] = "1829B";
  }

  list = make_list(
    "N9M07A",
    "F9A29A",
    "F9A29B",
    "T5D66A",
    "F9A28A",
    "F9A28B",
    "1JL02B",
    "1JL02A",
    "T5D67A",
    "F5S(4[3-9]|5[0-7])A",
    "K4T9[3-9][AB]",
    "K4U0[0-4]B",
    "F5S6[56]A",
    "L8L91A",
    "F5S6[01]A",
    "T0A2[3-5]A",
    "M2Q28A",
    "P0R21A",
    "X3B09A",
    "2ND31A",
    "F5S(4[3-9]|5[0-7])",
    "K9U05B",
    "CZ283[A-C]",
    "CZ284[A-C]",
    "CR771A",
    "CZ152[A-C]",
    "CZ29[4-6][AB]",
    "G3J47A",
    "G1X85A",
    "CR7770A",
    "CM749A",
    "CM750A",
    "CN577A",
    "CN2(1[6-9]|2[0-3])A"
  );
  foreach mod (list)
  {
    patches[mod] = "1829A";
  }

  list = make_list(
    "T8X(39|4[0-4])",
    "1SH08",
    "3AW(4[4-9]|5[0-1])A",
    "4UJ28B",
    "V1N0[1-8]A",
    "Y5H(6[0-9]|7[0-9]|80)A",
    "CZ992A",
    "L9D57A",
    "N4L17A",
    "A9T81A",
    "A9T81C",
    "A9T83B",
    "J9V(8[6-9]|9[0-6])A",
    "T8W(5[1-9]|6[0-9]|7[0-3])A",
    "M2U(8[6-9]|90)",
    "M2U(7[6-9]|80)",
    "V1N02[A-C]",
    "Y5Z0[0-7][AB]",
    "1DT6[12]A",
    "3YZ7[45]A",
    "4SC(29|30)A",
    "J9V8[7-9][AB]",
    "T8W(3[5-9]|4[0-9]|50)[A-C]",
    "A9T80A",
    "A9T80B",
    "A9T89A",
    "D3P93A",
    "M2U85",
    "M2U9[1-4]",
    "Z4A(5[4-9]|6[0-9]|7[0-8])",
    "CZ992A",
    "L9D57A",
    "N4L17A",
    "N4L18C",
    "M2U75",
    "M2U8[1-4]",
    "Z4B(1[2-9]|2[0-9]|3[0-6])",
    "F0M65A",
    "G1W52A",
    "P4C(7[89]|8[0-7])A",
    "T3P03A",
    "T3P04A",
    "J7K3[3-9]A",
    "T0F(2[89]|3[0-8])A",
    "T0G2[56]A",
    "CV136A",
    "CZ292A",
    "CZ293A",
    "E3E02A",
    "J2D37A",
    "J7K(3[4-9]|4[0-2])A",
    "T0F(29|3[0-9]|40)A",
    "G5J38A",
    "T1P99",
    "T1Q0[0-2]",
    "A7F64A",
    "D7Z36A",
    "E1D34A",
    "J5T77A",
    "T0K98A",
    "A7F65A",
    "D7Z37A",
    "A7F66A",
    "E1D36A",
    "D9L18A",
    "J6X7[6-8]A",
    "J6X8[01]A",
    "K7S3[78]A",
    "M9L6[56]A",
    "M9L70A",
    "M9L81A",
    "T0G4[5-9]A",
    "D9L19A",
    "J7A28A",
    "J7A31A",
    "K7S3[4-6]A",
    "M9L7[3-5]A",
    "M9L80A",
    "T0G5[01]A",
    "T0G54A",
    "T6T77A"
  );
  foreach mod (list)
  {
    patches[mod] = "1828A";
  }

  list = make_list(
    "A9U(19|2[0-8])[AB]",
    "D3A(7[89]|8[0-2][AB]",
    "A9J4[1-3]",
    "A9U2[3-8]",
    "CZ282[A-C]",
    "CZ276[A-C]",
    "A9J4[0-8][AB]",
    "D4J8[56]B",
    "CR769A",
    "E2D42A",
    "CX04[2-9]",
    "CX0(1[7-9]|2[01])[A-C]"
  );
  foreach mod (list)
  {
    patches[mod] = "1828B";
  }

  list = make_list(
    "D4H2[2-4][AB]",
    "D4H21[AB]",
    "D4H2[5-9][AB]"
  );
  foreach mod (list)
  {
    patches[mod] = "1826A";
  }

  list = make_list(
    "F0V6[4-6]",
    "J6U63",
    "W3U2[34]",
    "K9H(4[89]|5[0-7])",
    "F0V63",
    "F0V(6[7-9]|7[0-4])",
    "K9T(0[1-9]|10)",
    "J6U(59|6[0-2])",
    "J6U(69|70)",
    "K9H57",
    "W3U2[5-7]",
    "D9L63A",
    "D9L64A",
    "T0G70A",
    "J3P68A",
    "D9L20A",
    "K7S42A"
  );
  foreach mod (list)
  {
    patches[mod] = "1827B";
  }

  list = make_list(
    "B9S57C",
    "G0V48B",
    "G0V48C",
    "G0V47",
    "G045[0-6]",
    "K7C(8[4-9]|9[0-3])",
    "K7G(8[6-9]|90)"
  );
  foreach mod (list)
  {
    patches[mod] = "1831A";
  }

  list = make_list(
    "F5R9[6-8][AB]",
    "K7V4[23]C",
    "B4L(0[89]|10)A",
    "F1H9[7-9]",
    "E4W4[3-8]",
    "F5R95",
    "F5S0[0-4]",
    "K7V(3[5-9]|4[0-9])",
    "B4L0[3-7]A?",
    "D4J7[4-8]",
    "F1H96",
    "F1J0[0-7]",
    "F9D3[6-8]",
    "K9V(7[6-9]|8[0-5])",
    "V6D(2[7-9]|3[0-2])",
    "B9S(7[6-9]|8[0-5])",
    "F8B(09|1[01])",
    "T1P3[6-8]",
    "Y0S18A",
    "Y0S19A",
    "CZ025A",
    "CZ04[56]A"
  );
  foreach mod (list)
  {
    patches[mod] = "1830A";
  }

  list = make_list(
    "CQ1(7[6-9]|8[0-9]|90)",
    "CZ993A",
    "L9B95A",
    "N4L14C",
    "N4K99C",
    "E3E03A",
    "C9S13A",
    "CZ993A",
    "L9B95A",
    "N4L14C",
    "N4K99C",
    "E3E03A",
    "C9S13A",
    "CR768A",
    "T0G5[6-9]A"
  );
  foreach mod (list)
  {
    patches[mod] = "1827A";
  }

  list = make_list(
    "B9S56A",
    "B9S(5[89]|6[0-5])A",
    "F8B05A",
    "F8B13A",
    "F8B04A",
    "F8B0[6-8]A",
    "F8B12A"
  );
  foreach mod (list)
  {
    patches[mod] = "1830B";
  }

  list = make_list(
    "K7G(1[89]|2[0-9])A",
    "K7G9[3-9]A?"
  );
  foreach mod (list)
  {
    patches[mod] = "1829D";
  }

  list = make_list(
    "Z6Z11A",
    "Z4B5[3-5]A",
    "Z6Z95A",
    "Z6Z97A",
    "Z4B07A",
    "Z4B56A"
  );
  foreach mod (list)
  {
    patches[mod] = "1805J";
  }

  list = make_list(
    "CN581A",
    "CN583A"
  );
  foreach mod (list)
  {
    patches[mod] = "1827D";
  }

  list = make_list(
    "CQ1(7[6-9]|8[0-4])A"
  );
  foreach mod (list)
  {
    patches[mod] = "1832A";
  }

  return patches;
}

app = "Embedded HP Server";
get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:8080);

app_info = vcf::get_app_info(app:"Embedded HP Server", port:port, webapp:TRUE);

patches = buildpatches();

foreach key (keys(patches))
{
  if (app_info['Model Number'] =~ key)
  {
    fix = patches[key];
    break;
  }
}

if (fix)
{
  constraints = [
    { "fixed_version" : fix }
  ];
  vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
}
else
{
  vcf::audit(app_info);
}

