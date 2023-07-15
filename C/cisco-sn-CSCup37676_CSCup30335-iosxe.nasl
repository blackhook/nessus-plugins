#TRUSTED 569248b866cb3ae3c4cdb082cef1b7cf08cc1d6e00749d43de4a01171160ef365dfef4cdbcfb4a762303e5bf6cbb19476993e6be5522d0cb4273dcf7c8bcf6b5dfa01bfa8da293897d50294f4626384b2a102aa08a55efa988ab04d1ab0d55f66748ae6dec2305508b21d4c6ed9449f59590c0b29c8fd3f4419f2e926bd1c72e0d8991f6c65a2132e086031cb2deb0bff4ce151eea5a6fe416e1727f0485a9ab87ed7d2734a184ecb66ce616ad76acfa12d13d092df0c6e2e26f446b84a4b090e6798075933738cca9bc82e7b6bf0d4a4690868860b74fd3f43febce936464a6c925a258bf928fd0335ddccae4335d265e57f4c877b988a1ce2c07797ede807b2cb97c614cd75c546d193df10b485a1b4266b210d190ef7146f20f6c519eeadca097ac709c667d4792f6e1a53b7de291131e56f25534da36621b0f01595e8c07eea2f9e1173d9c9daf337fd2ddb1bc9febf4c2e01d8931724a0d9ac3a45143de5d2cc3bd41fd7310b00199b6aad4d800ae03199d68c32d634fed97188bc4e92e83df057a88a7b42bbb64792ee964deb5f7b39f890d9c913c58f3d4bb31832753691510600cd09ab57c68630582d0cec4952f645b6d06b00a9f6e7118dcf5280a0f74e44bc55971de96f94c1d8fe4d6904bed9388e5a8874175eebe3ab31eba2eb5a06ba983efd62d477a8bd121bff80ff783a2f91a29cdf2d4650eda1ec1d719
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83733);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-0710");
  script_bugtraq_id(74386);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup37676");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup30335");

  script_name(english:"Cisco IOS XE Software Overlay Transport Virtualization (OTV) DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Cisco device is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is affected by a denial of service
vulnerability due to improper processing of oversized Overlay
Transport Virtualization (OTV) frames. An unauthenticated, adjacent
attacker can exploit this, by sending a large number of oversized OTV
frames requiring fragmentation and reassembly, to cause the device to
reload, resulting in a denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=38549");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCup30335 and CSCup37676.

As a workaround, limit oversize packets across OTV topology.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# Check model
model = get_kb_item("Host/Cisco/IOS-XE/Model");
if (('ASR1k' >< model || model =~ '^ASR 10[0-9][0-9]($|[^0-9])'))
  audit();

# 15.3(3)S1 maps to 3.10.0 / 3.10.1S
if (
  version == "3.10.0" ||
  version == "3.10.1S"
) flag++;

if (get_kb_item("Host/local_checks_enabled") && flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_otv", "show otv");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^Overlay Interface Overlay", string:buf)) flag = 1;
  }
  else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCup37676 / CSCup30335' +
      '\n  Installed release : ' + version +
      '\n  Fixed release     : See solution.' +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
