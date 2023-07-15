#TRUSTED 7a06d185bb7baea2ab8c72dfc1dfd15b394b643b72d5e2522cfa3b078ebac61b2b877a54558d6b25092d96df511b6b67f6ae435a1bbf12904604bd90598ff7f66d61e43b09fe93af4ae965d783b07749f9fbdf4d0eef3adf442fad959eb441911d0e4d119ddde4f1c96b307c39a5a19f62d9d57922bff04a48a66cf444dea48a43bbf35cbc7e1f2c4b4f6f3d28c76721d68aa2f1c3e00868ea33cdc1e949ea5a6a90c3493f873c685517d11c26fbccefa10cb401131b48e6d1f26fc2560caef223fb5650871c30ece1e5e16fa8dab4f9f74840effb59166b7a3b2b1466b65a8b72735f1ceee9565616e072b9b894433b20628971be5851040a51655aac3d9d8374a44b78726848e63ba3feb18e984fafa036b8d5e6aa405253e94cc4ef25695038a9554b61a6997ca2159a83a7a226e29f25215c2f8f62d753ec14aa5fdde4dcf7bc2eb35bc64493b44fbd09c2a54470f7df88004029fc4237af927bb7f46819fd0259b365f30fc511013f731e4cf84cd687bff7861e566bc6d0cdb500dcde7fab052aa6d9886a194309f5da5d5dc516016b95d7b1eef533fb36887bc26b29be8e83bc5259733577dfdb05b0d35df1e5dfffc30ef1740eb2ec4887718aaa5cd7ab333cd483f5ff6bef6f2665a7a3aa3d41325205051609af0fc688d60da06be90d9396970939eb81b511ba861edfc6cfb786aa78d23c4030544d0f72abfaa511
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143263);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2020-1687");
  script_xref(name:"JSA", value:"JSA11084");
  script_xref(name:"IAVA", value:"2020-A-0494-S");

  script_name(english:"Juniper Junos OS EX4300 / EX4600 / QFX5 Series DoS (JSA11084)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11084
advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11084");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11084");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1687");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

if (model =~ "^(EX4300|EX4600|QFX5)")
{
  vuln_ranges = [
    {'min_ver':'17.3',   'fixed_ver':'17.3R3-S9'},
    {'min_ver':'17.4',   'fixed_ver':'17.4R2-S11'},
    {'min_ver':'17.4R3',   'fixed_ver':'17.4R3-S2', 'fixed_display':'Upgrade to 17.4R3-S2, 17.4R3-S3 or later.'},
    {'min_ver':'18.1',   'fixed_ver':'18.1R3-S11'},
    {'min_ver':'18.2',   'fixed_ver':'18.2R3-S5'},
    {'min_ver':'18.3',   'fixed_ver':'18.3R2-S4'},
    {'min_ver':'18.3R3',   'fixed_ver':'18.3R3-S3'},
    {'min_ver':'18.4',   'fixed_ver':'18.4R2-S5'},
    {'min_ver':'18.4R3',   'fixed_ver':'18.4R3-S4'},
    {'min_ver':'19.1',   'fixed_ver':'19.1R2-S2'},
    {'min_ver':'19.1R3',   'fixed_ver':'19.1R3-S2'},
    {'min_ver':'19.2',   'fixed_ver':'19.2R1-S5'},
    {'min_ver':'19.2R2',   'fixed_ver':'19.2R2-S1', 'fixed_display':'Upgrade to 19.2R2-S1, 19.2R3 or later.'},
    {'min_ver':'19.3',   'fixed_ver':'19.3R2-S4', 'fixed_display':'Upgrade to 19.3R2-S4, 19.3R3 or later.'},
    {'min_ver':'19.4',   'fixed_ver':'19.4R1-S3'},
    {'min_ver':'19.4R2',   'fixed_ver':'19.4R2-S1', 'fixed_display':'Upgrade to 19.4R2-S1, 19.4R3 or later.'},
    {'min_ver':'20.1',   'fixed_ver':'20.1R1-S3', 'fixed_display':'Upgrade to 20.1R1-S3, 20.1R2 or later.'}
  ];
}

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);

if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

override = TRUE;
# https://www.juniper.net/documentation/en_US/junos/topics/example/example-evpn-irb-configuring-ex9200.html
buf = junos_command_kb_item(cmd:'show protocols');
if (buf)
  {
    override = FALSE;
    if (!junos_check_config(buf:buf, pattern:"^.*bgp.*family.*evpn.*"))
      audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
  }

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_NOTE);