#TRUSTED 3c866068e14208c77cea4e90a9b819e60c705caaacb09b2251559f79200248d67d2065b31845563a592f365979a85de3e34dfc0e2b6ab8ce3a495a7fa01e13bb1d858ec81dfa489c378e478e0990cc335db563c3edf8094d436f2c8dd7bda64afba0bc50468c168f7818ec37f24a23095e2b579645008cbf26e0a7658135a183473227fc2ee912ff040c5dcef4d7314e6f080b7e4436b6041e998690194e6b3a586fb50e7f43b7039972a1fefa169e10675a7451a87a4260e58cd54ee6008eb545581f47a3f7cc505875463bb1b1b02242cf635b2b5ca89690b754597ffa60c33af49390334af7c748dc21e775f200c6c95ac1a4279a8810ee27fd66cbb24320e6215fdb930356c8b541d6f840fc59d43c247f586c9fb1ae32c55dec1a1c6507acdedbc8236a4250b89831a3c4b1eef5b0fff101e877df8576ba6b7182c0600fd785c8b93acc3380e6e4ddb2e746e205c3d1b800ce3de478c0d8940cf5a42d10de7b50c309a9bd811a6479ecc42ac93cb3b96505bdf80d3539a5485b58d8cbee3d4fdb9c3a525d02e7d56a82e97a4454642978d726d8ed1a1686ba8cd4b553a504d419080340766efa940340233d6fc4cc4f64d9b422aa5b8c2279e9afcac336ed84fd0812735ade0ec51e9950ad5f6a493739fe78cebd12d4d85e838e27abc4cc9f68aba0539067ece78d24768fe20dc89ff7397aa604de3484b4626ba9f330
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70475);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2013-4689");
  script_bugtraq_id(62940);
  script_xref(name:"JSA", value:"JSA10597");

  script_name(english:"Juniper Junos J-Web CSRF Protection Bypass (JSA10597)");
  script_summary(english:"Checks the Junos version, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device has a cross-site request forgery (XSRF) vulnerability in
J-Web. Successful exploitation of this issue could allow an attacker
to take complete control of the device.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10597");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10597.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

if (compare_build_dates(build_date, '2013-08-31') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['10.4'] = '10.4R13';
fixes['11.4'] = '11.4R7';
fixes['12.1'] = '12.1R6';
fixes['12.1X44'] = '12.1X44-D15';
fixes['12.1X45'] = '12.1X45-D10';
fixes['12.2'] = '12.2R3';
fixes['12.3'] = '12.3R2';
fixes['13.1'] = '13.1R3';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for J-Web
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system services web-management http(s)? interface";
  if (!junos_check_config(buf:buf, pattern:pattern))
    exit(0, "Device is not affected based on its configuration.");
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE, xsrf:TRUE);
