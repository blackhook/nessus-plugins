#TRUSTED 85125ed7f1be3a6f6683371e444dd463f5e40c968da0343fe0c0c07a7f5a5a99365c1ea64689285f1972c6ecb97f7beabe2531eb9f0e12ca324b4ca055c0e2b0a89b17a54176be57968a14672d909367bc4a1a57240e48a2bde4cee19d339d7013bc3e412443ec85cb3e8c232e49bdbd38410a0406b27a033cd7122ac1d93431d70a0dc03274d83ae12ea5a39c0e96d163019c69227efd0cff62faabd85e3b6d3ec9300b90480ab49835f0d92695faf138fb2fbf4eb5638352ce553fe5f7641b2c7d863c228f9360e792025a5b39db967e0ea2c0fe2a574f05c28f478e5a5d08b42e692320caa5a06a61bebb20e2fce875b24fd1767c96cea4f6123049be3fe1fa2d146cd319ccb554206ff910dd2ba36b7ab4f363572feaf9c824dbf132d3ccfc1b457aff9a9a919cc1daf4be431b92ac1fb8ab5bbcd34999d126b6a1818c972b2cf52d27d279be5817a5da46ba9e9ed8988835ae2fd577f66583f6bb0a58f2490c6d6c63de119081d67b817f21c60561871a6824e2ea0ddcad44013436b05d91af5850b2e2438fcef1bab33899179a76cab56c0593794b65e1d6c577b3b5336c353e18cac28e753964915b02b1e371c535ef99f2315d3ff1b6ed370dedf385296cea938ed6eb739fc6b7c3fe741bd7c4c66846750a5a0ce40d7f150f64a922ada2f33488066e7bda8194ca337d5939bc761a8bb5a0a066698f076f2a7c5b79
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139070);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/13");

  script_cve_id("CVE-2020-1639");
  script_xref(name:"JSA", value:"JSA11020");

  script_name(english:"Juniper Junos DoS (JSA11020)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is prior to 12.3R12-S15, 12.3X48-D95, 14.1X50-D145, 14.1X53-D47,
15.1R2, 15.1X49-D170, or 15.1X53-D67. It is, therefore, affected by a vulnerability as referenced in the JSA11020
advisory. Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11020");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11020");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1639");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fixes = make_array();

fixes['12.3'] = '12.3R12-S15';
fixes['12.3X48'] = '12.3X48-D95';
fixes['14.1X50'] = '14.1X50-D145';
fixes['14.1X53'] = '14.1X53-D47';
fixes['15.1'] = '15.1R2';
fixes['15.1X49'] = '15.1X49-D170';
fixes['15.1X53'] = '15.1X53-D67';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for oam ethernet connectivity-fault-management
# commands from https://www.juniper.net/documentation/en_US/junos/topics/example/cfm-ethernet-oam-ex-series.html
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (junos_check_result(buf) && "maintenance-domain private level" >< buf)
{
  report = get_report(ver:ver, fix:fix);
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);
