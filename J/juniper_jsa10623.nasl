#TRUSTED 9d27ad9850a1b31bcf5c3890996d1e76887107f4db87c14647d16beff7d9e95d8b2a16e6b8af1cac13f06453571d357c26f451e01072ad2a7dca36c8fa58edcc6c096c78765c89cabc4595d7688ddfe1036e245cce9099e684388a12c0c05f11d4e64b95b8be42a1b1270dafb8602cef864239ee2240667c4de00478abb2d7c7799179f04cb5d63fd813e103e55fcf3b16584eb11e7cac3fe94a449a419737e9c84a87aabafd3478121b44384fec02b14d7397296d1373e47a4b00f9fb7f836c489b75255daa9ab1cae57c7c22604f375d054ad3c6badf06cce72780c2e803bf624cd60b1ad369979832f68dd721ca480bf03ad1aca43db7d42c06f7dfddb50792f15d0e84a3c9a98d5914728772315f84f9b2645a2f8a73f1bccee03c9e62257fb382c2cb30dfa029c5aac0151c58588935cbd51cfd690c6fe84b29c25f7cbaf2771915143d3dbcf52a6bce864d4dae052e2da85d6d450e1155b4b3be9c036d3180db201de8f6465145becb8256961bf61f24e6d0f6fda18ea52e84f87183942153d55e1c73f4ad525f736a6f0de3ffff2311c05a332e20c6615a6b15b1ed36134f98489e0e6c74e7abac836210ea37deb3294e78830105780da8056c57c4ae8fdc622555cfd3210199bd51ea95160cf003c64f6eab0b94ed580ce1372547932fc790c2101dd6ce985aa051341bf6a6c265292ae33b7c6d028164160fcd57fd
#TRUST-RSA-SHA256 20c52dcbeb77ec587d0fcaeceb0cc556b9a54628977b0ebbfd1e7e71fe0152d4c8f753a269724f8d9cf87611d510189d0329b864c9b0c26e83cdc4996bd4287a7460750f7ca7ae571c46f599805999704b0c7660ffcf2613a58ec84daccd8fc09550adc3a04ca28406c5c0f3f3805bc3fc1d4b2dbc425513921a096ab25dbbdc042ef3c2393424566bdabf6c74517e07450e5587b8dd3d66258a88ce09faa229d5affd10fa9b6700ac1069a00ba21df6ae6fb8adc51305558cf053200aee2353b463e83700976b1ca4fd6876952db976e15f5aa13f6ddba76f92dd5979e4d4e29a1131051a7f7ffe187879def525b4d46b8cfc4faef7da1a42d2c3592c089863413e8699fd8489b9bef1d2a899f8d1b8b1a6432b0cd3ff191bd9499e4986b71b87ab2e93d1c26e6b95c0dabe2b8599f512d600a9288bbdda695778efd890711ee87b92cd6ce35e7acd8d404d58c1c385da916a251c18e09a75ee349b12d8721edbb2cf4de151aaa3cabae9e93b33331eea5e03a785030408dd8c895e44d76d395daa8044de6074a39ea7e038b57cae86bca6761d44644c0f5703f459c0e602aaef8f5e2621b08ef1582fae36450ebcb9e7b2553e4f7861bdd61020d36e3e235d8d25c211940edff60fbcf3bce4d3185b4c247deebbb7b8f239ec4d50d28ede3f7c5ee4c33c59b873ac98983f518c4705259aafd49f9e23fc9653aa3c823db6fe
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(73687);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");
  script_xref(name:"JSA", value:"JSA10623");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");

  script_name(english:"Juniper Junos OpenSSL Heartbeat Information Disclosure (JSA10623) (Heartbleed)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by an information disclosure vulnerability. An
out-of-bounds read error, known as Heartbleed, exists in the TLS/DTLS
implementation due to improper handling of TLS heartbeat extension
packets. A remote attacker, using crafted packets, can trigger a
buffer over-read, resulting in the disclosure of up to 64KB of process
memory, which contains sensitive information such as primary key
material, secondary key material, and other protected content.

Note that this issue only affects devices with J-Web or the SSL
service for JUNOScript enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10623");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10623.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0160");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2023 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if (check_model(model:model, flags:J_SERIES | SRX_SERIES, exit_on_fail:TRUE))

fixes = make_array();
fixes['13.3'] = '13.3R1.8';
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# HTTPS or XNM-SSL must be enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  patterns = make_list(
    "^set system services web-management https interface", # HTTPS
    "^set system services xnm-ssl" # SSL Service for JUNOScript (XNM-SSL)
  );
  foreach pattern (patterns)
  {
    if (junos_check_config(buf:buf, pattern:pattern)) override = FALSE;
  }
  if (override) audit(AUDIT_HOST_NOT,
    'affected because neither J-Web nor SSL Service for JUNOScript (XNM-SSL) are not enabled');
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
