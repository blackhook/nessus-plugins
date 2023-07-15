#TRUSTED 44cc42e959cd22306a67ce09ac52b1eecc953399dafe72a4f1d2cecb2613bfcc4ef252fa1fe188b8a1767e53b02ff5d171f9cf357d5d1d41e8495d5bfe36dee8a2ef36b8dff237b54c9a335b414751334ecbaa0ba45c62379d3b009ae732b7488f6d80de9ee5b7b1d8f797df7a533453758018627b4450b63329c589d6d87bbe42b0a5f32a9a53120f8d74786f27fdbe9bed14d892a74a29da86a01cbf940cef0b0ef72b5cd800930e1cf1565025ff34fe3d2978ac917eff2bcf821fc8f5c8e95bf8b278eb0011b664db9e90a8e2f0fe63d0d25fc9f6a5427eb7a0768d9ab0231b355d63a28328c3c35f7ce4cb8325188a6553efa6e5c4e3bdd530ced8c5c1a26be24eee465dbc0eff25022a193122c0fa97566128b9b95f05cc7df27b22b2185d4cf802759a8f3e74ab3b7e27f9b0437ab2c6bb8741725590f189b9a51e7c678e3b061031a2d42948832cab8d4afb6d843c1dcaa41b922675240fae375d7722a6ef9825d98d68bb5a72e265dbd2916b23342fc8066056709b62e4f100119799fe49676a67a9b8ce258226ffbd1700ec0cc68fcddc85fb49d19c3fcb1edf03d5556952f3b183d698fc2a1f27c39921128796c5403ce76a0125e9e153075b5c157fa955a2e8c077097686f843d707ce84a14a4e0cdd6481a5dbe08c471511c2b53727751c58da0184a6ed7e5bc6193cf25ecdaa259d6334d648d7cd24f488eaaa
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141845);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-1679");
  script_xref(name:"JSA", value:"JSA11076");
  script_xref(name:"IAVA", value:"2020-A-0467-S");

  script_name(english:"Juniper Junos OS PTX/QFX Series: Unexpected Packet Forwarding Vulnerability (JSA11076)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is PTX or QFX Series prior to 17.2X75-D105, 18.1R3-S11, 18.2R3-S5,
18.2X75-D420, 18.3R2-S4, 18.4R1-S7, 19.1R2-S2, 19.2R1-S5, 19.3R2-S3, 19.4R1-S2, or 20.1R1-S2. It is, therefore, affected
by a vulnerability as referenced in the JSA11076 advisory. Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11076");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11076");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1679");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos_kb_cmd_func.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

if (model =~ "^PTX" || model =~ "^QFX")
{
  fixes['17.2X75'] = '17.2X75-D105';
  fixes['18.1'] = '18.1R3-S11';
  fixes['18.2'] = '18.2R3-S5';
  fixes['18.2X75'] = '18.2X75-D420';
  fixes['18.3'] = '18.3R2-S4';
  fixes['18.4'] = '18.4R1-S7';
  fixes['19.1'] = '19.1R2-S2';
  fixes['19.2'] = '19.2R1-S5';
  fixes['19.3'] = '19.3R2-S3';
  fixes['19.4'] = '19.4R1-S2';
  fixes['20.1'] = '20.1R1-S2';
}
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
buf = junos_command_kb_item(cmd:'show configuration | display set');

if (junos_check_result(buf) && buf =~ "tunnel-observation mpls-over-udp")
{
  report = get_report(ver:ver, fix:fix);
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);
