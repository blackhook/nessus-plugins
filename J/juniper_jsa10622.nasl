#TRUSTED 0a7dcb4d8190f2d61adb3eaba8ac104ebe5019a96e7f220047e740986b4f1d64823dede796bbd82ae555014097431553051a7420b0777137cb859474846c22a89f587bf72851e23cd8d496012b516aa872962a58368f615b359e8848ec2de8bbc8aa96bf50b5e6452925644305b0614ec3df9527b09df2a4ca1ffcfabf41d3ffa24d015aec0b1eccf0e6d19ea1fafe5eece775f88a49061e41f21bf53f4aaa57ee7c8320c1a3eaa64af1fb5e205f533ed84256c8546e90bae9b1222f21936188568143095f2f66ed03765cd07c6a23f0c02de6fa7481a6a16122cd9912661514bca8b58ba386d7fda88fc3e0d45cdc41eb1def112e8b308fe898eb9b6194bb13fa96c41616e18e7ed11fd27abdadab4e4757eec691d2380bf13f1c8a934c9495d998805d6196936b0d7821a3a936445d263b124eb36df1b3257eb1d1e3be27f99834c14ddb2356bfb078d6bceaabb24836c5f165e051254368affe6b8d5ad15f5dabec162cf81ccdbde0c05e2047a124560aa8d2511b571b49f4e94c4086b395e9f20324941f6bc1917747ec0beaa5b1a9b275eaa87f419595e1a2342409bd4ed638d3fb4bb17b819bfccf30a0c8e00d5117aaf98d6d5fdfc534b149bf0ae26047591bd65f9d62072e2b57128ada99df2cae903dd0870f0ef19d7b5c5a3ae93d0e6ebd8db5c3aa39a295a3791fb5a2a3fd9ae2fc45f0ae7769a297412d6e0018
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73496);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2014-2714");
  script_bugtraq_id(66760);
  script_xref(name:"JSA", value:"JSA10622");

  script_name(english:"Juniper Junos SRX Series flowd DoS (JSA10622)");
  script_summary(english:"Checks the Junos version, model, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a denial of service vulnerability due to improper
processing by the Enhanced Web Filtering (EWF). An attacker can
exploit this vulnerability by sending a crafted URL to crash the flow
daemon (flowd) process. Repeated crashes of flowd can result in a
sustained denial of service condition for the device.

Note that this issue only affects SRX series devices with EWF enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10622");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10622.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

model = get_kb_item_or_exit('Host/Juniper/model');
ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

if (compare_build_dates(build_date, '2013-12-17') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['10.4'] = '10.4R15';
fixes['11.4'] = '11.4R9';
fixes['12.1'] = '12.1R7';
fixes['12.1X44'] = '12.1X44-D20';
fixes['12.1X45'] = '12.1X45-D10';
fixes['12.1X46'] = '12.1X46-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for Web Filtering
override = TRUE;
buf = junos_command_kb_item(cmd:"show security utm web-filtering status");
if (buf)
{
  pattern = "Server status:.*UP$";
  if (!preg(string:buf, pattern:pattern, icase:TRUE, multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'affected because Enhanced Web Filtering is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
