#TRUSTED 21f1198bf57d353a131c1c517066fce3304595407ebc0019d98d508a2d77c24ab1ba863c8f38727ea48c49713fb4ccf0adf5dfc30d3d9c42e5e2c62b7f14d433d2f0200427cb2a9d436f12bdbee08524928060707100aa05f61ffbd2e5a0a152f7b8e5a0f9340181773cc54ebe9b418d03c08345b3e14693bea22b153878152d7c0e8c0174417d9a88ab1f27f470c9b9195a32fc767a0ca3d2a6e55d014174f4c696f36fa193f015cde8c0e3ee185994dbd36cdb679c33c9e6e15ed4d48f0890e23f6687ada90fe4a00d91eaedbf9fb0c25e2327cfce2fe744f42063e5e23bcdf129a5b91cbf864b28cd1012803c154f76dd56badf82368ac04b0e52baa345a49081bd80c4e665e0716b9b56e3d7cf807d8629f79a62f4f5c5f5e97d2dda67b0a6c3ff5bebc796e8d229cffe4e351025a0150edb946fecdcee905e6e7ca8f87057ded0de45269d0a62f45340db872b21e2a6c6175c179f249f05f958a06094103f1964806c2e931be125c8f7ed02b3e364cfabf9f67a3fae0b5bc080b854807be2fdf615ffb0db4e94be7504ce56a937e18c72ebcea9b50d7ba5c99900f6505e1e95f3765f92dfdaa1e9c2e231271fdf549219c4f1d53c71be886b3018dd8c89cf7997daf5861b8b045e7f0794edfd81597d46fe2421e813d73e379879b0957253d5e84e828393ae8d7b56cc2a03d5725470d1bce9db7ba67d6da66bddd0ad33
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134893);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/14");

  script_cve_id("CVE-2019-0048");
  script_xref(name:"JSA", value:"JSA10942");

  script_name(english:"Junos OS Firewall Filters Failure Vulnerability (JSA10942)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is EX3400 Series running Junos OS prior to 14.1X53-D115, 17.1R3, 
17.2R3-S2, 17.3R3-S3, 17.4R2-S5, 18.1R3-S1, 18.2R2, or 18.3R2. It is, therefore, affected by a vulnerability. When a 
firewall filter is applied on the loopback interface, other firewall filters might stop working for multicast traffic. 
The command 'show firewall filter' can be used to confirm whether the filter is working. as referenced in the JSA10942
advisory. 

Note that Nessus has not tested for this issue but has instead relied only on the application's 
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10942");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10942");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0048");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('misc_func.inc');
include('junos_kb_cmd_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fixes = make_array();

model = get_kb_item_or_exit('Host/Juniper/model');
if ( 'EX43' >!< model)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);
  
fixes['14.1X53'] = '14.1X53-D115';
fixes['17.1'] = '17.1R3';
fixes['17.2'] = '17.2R3-S2';
fixes['17.3'] = '17.3R3-S3';
fixes['17.4'] = '17.4R2-S5';
fixes['18.1'] = '18.1R3-S1';
fixes['18.2'] = '18.2R2';
fixes['18.3'] = '18.3R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# If it has only TCAM optimization enabled:
override = TRUE;
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  pattern = "^set system packet-forwarding-options tcam-group-optimization";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
