#TRUSTED 5a3cf0e31fbd4e363fcf564db8f378e085aca6d82fa14ee1cc657891fffdc50219fe9b80898930eac6b5d21ffb7070bc20231834c19ad45fef1c3d0621f572cfe549dbe98f94e146d9ccd4cf0e6306dd58b8cecccca68ec01e7e4694e04b28cf30455d9578a8ecba2be53ee2de6468ad364021bdd132fa35ac6478a27e4734f726eb83c4822b1cdb1d833a0f2fa556209e2f763848b751567ca7cd243c0c5f362845ba8cbf2d0c472b7adb5a9cdb41f24d4b9432443d82a3d9ee25d10c73554cb6eafe2de809d8e3e189a49100e9756cc7212963ea5260066720f13262374f1e9077fb45793bd1cdc87d815de87dd0bce3d8253f798957e333dce3bf763452c8099e3264d76ff9faf52c27c75ddb41d5c57c802ab4287a914f36c401fb9c3cf6381718916c0dfcd2b33dc87fc7eb45c6f9bbe0b8f6e4ed7cf555d7c78db0cd02c6f61585fcf2230ff262afb58f26498ad9271a25e717f6c2ad3fb5b2ef5d112459a9013b3700be079b35dcdf4ea0c7ea8beb04c784cb4abcd1f6ccb8058a6b165c51df10b6bcd7a950886c9f6e7733d2e494eb5b18be1fc83dfaeb2a947b6940d2489f319320b99665a9442e79447cbf46178a6e3a1564011aeadc117fdf7cfda223bd5f2f5f2567806cec07bc058f568d58c337354b60b596337c4dbe88fc92e06ec3a44f69d7bb999ced58578b5d4e4102764880ba36e1fca3471e30adf131
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70476);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2013-6015");
  script_bugtraq_id(62963);
  script_xref(name:"JSA", value:"JSA10596");

  script_name(english:"Juniper Junos SRX Series flowd Remote DoS (JSA10596)");
  script_summary(english:"Checks the Junos version, model, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos SRX-series device has a denial of service vulnerability related
to processing particular TCP packet sequences. A remote attacker can
exploit this issue to cause the flow daemon (flowd) to crash.

Note that this issue only affects devices with ALG and UTM enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10596");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10596.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
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
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

if (compare_build_dates(build_date, '2013-09-18') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');
if (ver == '11.4R5-S2')
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['10.4'] = '10.4S14';
fixes['11.4'] = '11.4R6';
fixes['12.1'] = '12.1R3';
fixes['12.1X44'] = '12.1X44-D20';
fixes['12.1X45'] = '12.1X45-D15';
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# UTM or ALG must be enabled
override = TRUE;
if (get_kb_item("Host/local_checks_enabled"))
{
  buf = junos_command_kb_item(cmd:"show security utm web-filtering status");
  if (buf)
  {
    override = FALSE;
    pattern = "^\s+Server status:.*up$";
    if (preg(string:buf, pattern:pattern, icase:TRUE, multiline:TRUE))
      override = FALSE;
  }

  if (override)
  {
    buf = junos_command_kb_item(cmd:"show security alg status");
    if (buf)
    {
      pattern = ":\s*Enabled$";
      if (!preg(string:buf, pattern:pattern, multiline:TRUE))
        audit(AUDIT_HOST_NOT, 'affected because neither ALG nor UTM are enabled');
      override = FALSE;
    }
  }
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
