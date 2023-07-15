#TRUSTED 27662d5119c68fdb0a2ca2bbc7707ce5d113c2e6add786dafd74f0daec3e3c7a4ba1731c9744240861b6fe28b91344686c3d65c343c4f14ac2171b1b101691e816e1c0518b1a54f8a2066f362deac5ecb8bbf283cc52d01e4232253a3c7d88e9df71b79d7717d560640e9d675ad7d46474ffa443d26b3cb321139f553498910009e190127737b35bb9e44ac6c8e3570f15463e1ba0fc0c2bdf88228910ff292523d0a64f7ea867d85c5b4c2e40ee91b73995f551b06e3df53044d982c97cf0f7b97ad1ee5149c4c09f815e4e604c16898e4b5701f78061decb5e006a02a70a3e62ee1f587627db2e4b759dadf7a145958754839d9d15d9d88d33079cf047547fca7ccac9a42711ceb97a7d91245627e272b72fd2af651b4c7dfdf66874596ae4adc56af6513e58d7ee51271381bccbd4b538e2b43203828b51363191f88c2c192129de8baf352d1fdeee1eb3cb2c6869e68e1ba10f183a84b759b5b7c13a186696cf37b7c05d6cad8d7aa742c337843adc575a62d6de831f1441aaf5d680f3d5d58a17f00b9821c8721f1079956e5ec8c794e6fa3a2767e300dc4e243f5d7e7be792c4b39221cc8ef6ee8cfcff7528d6c6bf20911e9739137fe4eaacd25fc79d6bc0c3cef9706fcdf752506ce1142bbfa4fd3a3194d63dde6c5e5c4d154b6dde9dcea4415e5123e99c0288a00cdbcf75c2e0a79a47b1597ceea56422eb6c9c81
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144978);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/26");

  script_cve_id("CVE-2021-0215");
  script_xref(name:"JSA", value:"JSA11105");

  script_name(english:"Juniper Junos OS Denial of Service (JSA11105)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11105
advisory. Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11105");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11105");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0215");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/14");

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

model = get_kb_item_or_exit('Host/Juniper/model');

if (model !~ "^(EX|QFX|SRX Branch)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

vuln_ranges = [
  {'min_ver':'14.1X53',	'fixed_ver':'14.1X53-D54'},
  {'min_ver':'15.1X49',	'fixed_ver':'15.1X49-D240'},
  {'min_ver':'15.1X53',	'fixed_ver':'15.1X53-D593'},
  {'min_ver':'16.1',	'fixed_ver':'16.1R7-S8'},
  {'min_ver':'17.2',	'fixed_ver':'17.2R3-S4'},
  {'min_ver':'17.3',	'fixed_ver':'17.3R3-S8'},
  {'min_ver':'17.4',	'fixed_ver':'17.4R2-S11'},
  {'min_ver':'18.1',	'fixed_ver':'18.1R3-S10'},
  {'min_ver':'18.2',	'fixed_ver':'18.2R2-S7'},
  {'min_ver':'18.3',	'fixed_ver':'18.3R2-S4'},
  {'min_ver':'18.4',	'fixed_ver':'18.4R1-S7'},
  {'min_ver':'19.1',	'fixed_ver':'19.1R1-S5'},
  {'min_ver':'19.2',	'fixed_ver':'19.2R1-S5'},
  {'min_ver':'19.3',	'fixed_ver':'19.3R2-S3'},
  {'min_ver':'19.4',	'fixed_ver':'19.4R1-S2'}
];

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

override = TRUE;
# https://www.juniper.net/documentation/en_US/junos/topics/example/802-1x-pnac-single-supplicant-multiple-supplicant-configuring.html
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
  {
    override = FALSE;
    if (!junos_check_config(buf:buf, pattern:"^.*dot1x\s+authenticator.*"))
      audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
  }
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_NOTE);
