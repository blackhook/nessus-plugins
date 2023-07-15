#TRUSTED 3da28f77c829f1f12174ba6f837a440132aee239f48ed54d02e174ec79d3a7fe2db4fc152716d7ff5bf741804750db3aaeaeb3efecf996893db125355634de89c9a2cf70f3b158b6d528a80d1c999dacf5891b341a96525da89e6aac33bf314485127d245c6ea691d93135baeff14a9df4e580b834997f76b922a54a9b822cf7571d731a371ca52a17d21c094169a12650da5b05e5f2bbdad18ad8d3e4c4d2b75c71c873e9418077707f32229672cd7a8e8da0fca2267858439f78bc46f7af60c09b5fbbf392b7684360a5ed4ba9980cb20582458259ad52841d593d48cf0fcabc2dd17a4b3278ac64653754fc813a376c24f47448eefe1e6f4bcdce19214205f69f75c7ffaab43eb35f93e2e5bb41efc707022bff41d29bb3c94a150fb8811c5625017ca96f8757ffe8867737f8c6a0ffab258d659ad35c9d9a13c759b30ffd688a41ffd9246a0045e6eb65d8b96c49c9981ebc3398b4fe7ab6780c470901eaaf97926a228b594cb313467ddb76ccc115cecac5ed656b019a2a78ffd33fd66f29af9828151442d7d98be4d6b23b31273c8268a3af34ee8decbdbc9eb66fceed2d991e82bb457391b61f198a3a39755a4fe69a97068a0991221ab75cf9c96810b55f987de2073c0a53ddccbbd80fe3cb1daf1315f1336ccf0f62eb84d59756dd702b44e6048dca96d4e312ee3aad7b1856cf1fe9598e8bf726e53de8ff83bfde
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76502);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2014-3815");
  script_bugtraq_id(68551);
  script_xref(name:"JSA", value:"JSA10633");

  script_name(english:"Juniper Junos SRX Series SIP ALG Remote DoS (JSA10633)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a denial of service vulnerability. A remote attacker,
by sending a specially crafted SIP packet to an SRX series device, can
crash the 'flowd' process.

Note that this issue only affects SRX series devices when SIP ALG is
enabled. All SRX devices, except for SRX-HE devices, have SIP ALG
enabled by default.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10633");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10633.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

# build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');
# if (compare_build_dates(build_date, '2014-07-31') >= 0)
#  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['12.1X46'] = '12.1X46-D20';
fixes['12.1X47'] = '12.1X47-D10';
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for SIP ALG
override = TRUE;
buf = junos_command_kb_item(cmd:"show security alg status");
if (buf)
{
  pattern = "^\s*SIP\s*:\s*Enabled";
  if (!preg(string:buf, pattern:pattern, multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'affected because the SIP ALG is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
