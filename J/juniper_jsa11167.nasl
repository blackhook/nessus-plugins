#TRUSTED 189bd305cb7288793968d490b5b226d84de7ddc98a015d59d27403edc4e5a23a808bc88751b4971810c3e3a3f40898bbb7fcb02fe672735a3191ec1a3422f581e86ae70c17e1e1a2eae2b6f5982bd09257abdd445902f3805004769c541ee37b6497d730bc49a1431d9447eb36cf967434aef704301f7edcc02e55128dd9f2faa89f83b53d4a525104d5705d296db525505fa6ea2b7f2fe0ff314d5c154a32fb49dd591a7c48bf51e9b8f3931512dcf4d118006a2bfe4399bd0f6f42d1d574862bb489852471ac5fe1ea865cc8fc170de596125e5ced45c6e85370c25b5fe6d5c7bd0aa067ea3603eb6d6c631ddd45ac449f8dd85ef724872f5f89536195714d2edf02f82d2e875aaff0a4f2ed0aff71788cfa77bb5adf0d8983bb36b6e378cdd64cce58e7837342ac53aaea4cd9e7d1b901f40b5fbd13e67d305bca39c1262dd97f7cca61427c0fe1561d8905f6d041502e8c3b653d128344a27c67878ce9a9bc85c8c08c2a1c11ed7d6ae36e9cf268f703a4d72ed6307bcb21c044cc65c6093d171ccceb3db278fae6905898ab318cb86f2cdfce00a10459e8a4b712148c63fea029c326497e7fa6e9d2431b885e65dbfaca1527b3882568d0d576a9f609342a36a6ac842917e0f9f859e283e1e91e4e8a1601275be7faf2822af7ff3eebbd2fa90b35a4f63eac264ec54684784b2e82520f2d376e7fe0f9cfaaa41ef60434
#TRUST-RSA-SHA256 418d314a001dd9b2ceac85dc1f34c5932c8235cd1ae8dae62b1b60d349f704709aacb78c1d428828a750fd2e48c4d40bdb3b36b528496a7f92d8596fd9e2a4edb65e4b108ad1a74b4bba4e6544a716ad0593488655718b4b3f698805cb9f4e2e49d50bb50507a8a571d883921ed6490322815ccef1f4dc632bcdf68290222b1efab47f578b3b4fa50adae88790de0878e7588c404d2390cc2362cbae23184a0a61f31c7bbbcf8be91ca848e1aebe8d41d77fabc90cfd5ce909d29f79d7d226fbf84a02f99c8408afa5afcd1f3484f34b8762a90d669b07c260352081757ebd45493b95a56b2634df64013b5c28f17b658b8ea3ca8ac141f0c712aa09a568ba79c2f8723ac8dafb3d509f7c96f354ce83c3ad220a599ac3896b1aff20f6c40846ad1eefe649a91760226ec465720438caf46420e4629cf48e9da6876adf54f8c052ef1e8d3cf178a557a49bbaba7e1fbf71ded965b0d5141b524120c4cac8412965eabb2035ef5a08f6d3219301fae03630ba2c1fae024f8dd1d2b41ec83806223c8573458269b533f5e45159560182e0146adb28b1292feae475171f648d7182cb511778f26004aedd3aa6e3203692884cf6c07ce1d5addcbd6a5932d54668b7b539c737f29790a8e778352e6c162fdc95dc7589e68d318513b6815496d7733f0ce1a438354875f9849f9e9016c4d1b2c5b7a40043e72c8fe590a6de921ff2a0
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149967);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id(
    "CVE-2019-9511",
    "CVE-2019-9512",
    "CVE-2019-9513",
    "CVE-2019-9514",
    "CVE-2019-9515",
    "CVE-2019-9516",
    "CVE-2019-9517",
    "CVE-2019-9518"
  );
  script_xref(name:"JSA", value:"JSA11167");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"Juniper Junos OS Multiple DoS Vulnerabilities (JSA11167)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by multiple denial of service vulnerabilities as referenced
in the JSA11167 advisory:

  - Some HTTP/2 implementations are vulnerable to window size manipulation and stream prioritization manipulation, potentially
  leading to a denial of service. The attacker requests a large amount of data from a specified resource over multiple streams.
  They manipulate window size and stream priority to force the server to queue the data in 1-byte chunks. Depending on how
  efficiently this data is queued, this can consume excess CPU, memory, or both. (CVE-2019-9511)
  
  - Some HTTP/2 implementations are vulnerable to resource loops, potentially leading to a denial of service. The attacker
  creates multiple request streams and continually shuffles the priority of the streams in a way that causes substantial churn
  to the priority tree. This can consume excess CPU. (CVE-2019-9513)

  - Some HTTP/2 implementations are vulnerable to a reset flood, potentially leading to a denial of service. The attacker opens
  a number of streams and sends an invalid request over each stream that should solicit a stream of RST_STREAM frames from the
  peer. Depending on how the peer queues the RST_STREAM frames, this can consume excess memory, CPU, or both. (CVE-2019-9514)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11167");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11167");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9513");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'16.1R3', 'fixed_ver':'18.3R2-S4'},
  {'min_ver':'18.3R3', 'fixed_ver':'18.3R3-S3'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R1-S8'},
  {'min_ver':'18.4R2', 'fixed_ver':'18.4R2-S5'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S4'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R1-S6'},
  {'min_ver':'19.1R2', 'fixed_ver':'19.1R2-S2'},
  {'min_ver':'19.1R3', 'fixed_ver':'19.1R3-S2'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S5', 'fixed_display':'19.2R1-S5, 19.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^set system services extension-service request-response grpc", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
