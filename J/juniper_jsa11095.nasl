#TRUSTED 65e1b695ddd98da108376b4520b6726ecf0d02d425c9c8e2e0498fa9bbef0dc700761415d16afd99978d0e1d0b79d3e08421d7669a69a6c2ad306f7a14e85bc8e60cf56de71b559e683749e6e6cc32662a5717c3bcf298bcf1cbca75f3afa23c9e2891a0f132a01736530c004eac4817179da150c31e7e52cb8b399e32b28b21c31619c34e6137d17983f4ca2eb3f5094f5c124fdb17d61e1ae2046cdd46c06e27b1f3a8db1bfbbee18d230679b8559898b2cbe4a722b5ead226ec23840d59e2815d2498e11d0d32fd3eb477728af97b6031af9d931f991a3db5c63f53f4e9550a9db325dd339f79674095dbcf7633288415e103487f24715867d94d0eac3ca47b3779b4d7773fe6afb5e9cc0e6fdd216e14823f76be4520191c743dbe36acacb1b6f990f5c699a81073aae6212a98b25141633ac6f4f12edbdd6e98fa486bee66fe5a08b81e133917e623164ac1b9c8f091e7824ff04a12029ffbd374085f66bf2e72b1e5e6c07e525e22cf2c7326ee91df9fff0ccd332b39affb2a2fcc270f5d0ba8b844de808890b25254f92fc214636abcd47779a9e234465dac8ec385f968f43e4be62b3638de44a5b47fa388e42259f94e1ab9286dbafb309f0a5740792c728c70b79b011d26141a835523c72743321c895da75ab6205941dcd9f617294cbf817fcb0643dc3bc7426a67246d11ab8e560cd90aef5e7f02a228fa451dd0
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150137);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2021-0205");
  script_xref(name:"JSA", value:"JSA11095");

  script_name(english:"Juniper Junos OS Blocking Unexpected Traffic (JSA11095)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11095
advisory. When the Intrusion Detection Service (IDS) feature is configured on Juniper Networks MX series with a
dynamic firewall filter using IPv6 source or destination prefix, it may incorrectly match the prefix as /32, causing
the filter to block unexpected traffic. This issue affects only IPv6 prefixes when used as source and destination. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11095");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11095");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0205");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^MX")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S10'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R3-S3'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S11'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R3-S6'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S4'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R3-S6'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R2-S2'},
  {'min_ver':'19.1R3', 'fixed_ver':'19.1R3-S3'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S1'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S5'},
  {'min_ver':'19.3R3', 'fixed_ver':'19.3R3-S1'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
#set services ids rule simple-ids term 1 then syn-cookie 
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^set services ids", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
