#TRUSTED 571cd67de539e358b59fd7a0571aa323e580114ccb71c328d1546aa9e3249bdd235230a2b35c35af9b1f6ad473f0c983fabc7057c12f19dd9fe3ece7405f2878b303cfeb9e959ad1b43d897be07c78d18761fa4efa7acf9fc4fc160ce5fc67653e66b922511a1a732754ceef66db45ea133ade38dfe8dde69515d7a05fcc1fdd4da4bec36212e50923b9bb4f5a907fe3fe700cffe45d09eb9ec6647a614fbe9d1e8a863974576004fdf8dd17eb912558ff47051312cbc0df2cdef0e35d50f30c0f5d20599ff0380d12042baa9ff1b6b2ae2007baf84321e691fdf9b174de407907b07a625289f55e95744f5cc988bcfc0c21d4663fee34a12916cab30af2da8073973c550bed2d3b3fdd368040c128d7350e123f275e0e5cb1f9421c3dffb34e273b848abe06e36dfe55d9dd6c0ec8b7a580fc5f8c3d15e8b870a315a8472ee6a4c195e057aad64dbc8b8aba67fe5818a8d576cfd765613935cb2545da0df6adace5a43c8c9e0394706a6833d64858edd7b0b3d2a2cb12411252cd656abf193df22ed11085705ec771dea32e011af040d7affc4d5e192bbda36e13465e535e8270c69324d02354a78a9ad2b6ea0c22007e74abc10545463fefbb1a3882b90ebadc922057e9fbaa12cb968bad1d75c2bba734453b8bc4eda52f9c34b456754f6f9954f3e54b7a7a2fa168c0525a6ae8648f65e210c8331184b0b6e5bfef15367e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86607);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2015-5361");
  script_xref(name:"JSA", value:"JSA10706");

  script_name(english:"Juniper Junos SRX Series FTP ALG ftps-extension TCP Port Exposure (JSA10706)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos SRX series device is affected by a flaw in handling the
ftps-extension option when the SRX secures the FTPS server. An
unauthenticated, remote attacker can exploit this flaw to expose TCP
ports for arbitrary data channels.

Note that this issue only affects devices with the FTP Application
Layer Gateway (ALG) enabled with the ftps-extensions option.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10706");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10706.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if ('SRX' >!< model) audit(AUDIT_DEVICE_NOT_VULN, model);

fixes = make_array();
fixes['12.1X44'] = '12.1X44-D50';
fixes['12.1X46'] = '12.1X46-D35';
fixes['12.1X47'] = '12.1X47-D25';
fixes['12.3X48'] = '12.3X48-D15';
fixes['15.1X49'] = '15.1X49-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# FTP ALG w/ FTPS-Extension must be enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set security alg ftp ftps-extension";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because the FTP Application Layer Gateway (ALG) is not configured with the ftps-extensions option');

  buf = junos_command_kb_item(cmd:"show security alg status");
  if (buf)
  {
    pattern = "^\s*FTP\s*:\s*Enabled";
    if (!preg(string:buf, pattern:pattern, multiline:TRUE))
      audit(AUDIT_HOST_NOT,
        'affected because the FTP Application Layer Gateway (ALG) is not enabled');
    override = FALSE;
  }
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
