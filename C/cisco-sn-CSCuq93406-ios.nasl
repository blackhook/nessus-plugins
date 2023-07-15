#TRUSTED 12435477e7e36d2ffecc0f92ec6f07be20a1197c364c6ee4f6cac71e0f29d198edc7c0b063d2b0fb0ff717cb6ab8c02602ebe2ce199313941e99194d77aea44750b852c2a4872cb5a6361d011799aa91877f56f70a18e2e3fd4d41abb006b483a561a1cd7208cea59292e8ca2e89dc4052a651a679a3a5a121e28eb35a7c0e057a6ea5294641627db92510c95e3aaed9f1b05d826795c388bb1c14bc8d60f09062ae2b92aac9c793125f28e65b74626909f35eda60a77198208f6c4662469474b3237368ba780cc57b2296922f6b54fa66c6de0d93497cda609ac759bb17c9210376ad72172eb85f05956cd8a66cc55c987d3762e242283d742f8224914d4a7c1c9febbbebadac91e04a6415688bc5eb9899c839777ba9a8bae1ab34dcc273e7ed4f509fe0811e659c1624501c6af0e06b4b78b9b0292ddf462287b1130bb7445fa353d5bf2898540a8a6c65503222a26c87594f13999a039187dba9633c817fccfdac67bda46a54fbb9f9c084d58cfef3bb15215272cbf93f9a16ff871a8c9f078012ea3dcf9cd47833a2a2ad60e44eec243596359f71c141c8ef6cfb8b0641b3ba688e5ac724a74691bfbf8bb2a568334abedd437fcaa95cdb02ef1fb2aea87aa01adf9b59ee5a3ee28c87b68c7bef96fed8212a596438d7f130c9c5d1eacdc2cdf47ee66a840a18bfc2a7171a89d8d03fa8d732d434a8256711fbb9512cd1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78918);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-3409");
  script_bugtraq_id(70715);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq93406");

  script_name(english:"Cisco IOS Software Ethernet Connectivity Fault Management (CFM) DoS");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Cisco device is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is affected by a denial of service
vulnerability due to due to improper parsing of malformed Ethernet
Connectivity Fault Management (CFM) packets. A remote, unauthenticated
attacker, using specially crafted CFM packets, could trigger a denial
of service condition, resulting in a reload of the device.");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=36184
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8080ca42");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Notice.

Alternatively, disable Ethernet Connectivity Fault Management (CFM).");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");


  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

# Check model
model = get_kb_item("CISCO/model");
if (!model) model = get_kb_item("Host/Cisco/IOS/Model");

flag = 0;
override = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (!model)
{
  if (version == "15.1(3)S2") flag++;
}
else
{
  # 7600: 12.2(33)SRE onwards
  if (model =~ "^7600($|[^0-9])" && version =~ "^12\.2\(33\)SRE($|\d+[a-z]*$)") flag++;
  # ISR-G2: 15.1(1)T onwards
  else if (model =~ "^ISR-G2($|[^0-9])" && version =~ "^15\.1\(1\)T($|\d+[a-z]*$)") flag++;
  # ME2400: 12.2(25)SE onwards
  else if (model =~ "^ME2400($|[^0-9])" && version =~ "^12\.2\(25\)SE($|\d+[a-z]*$)") flag++;
  # ME3600: 12.2(52)EY onwards
  else if (model =~ "^ME3600($|[^0-9])" && version =~ "^12\.2\(52\)EY($|\d+[a-z]*$)") flag++;
  # Cat4k: 15.0(2)SG onwards
  else if (tolower(model) =~ "^cat4k($|[^0-9])" && version =~ "^15\.0\(2\)SG($|\d+[a-z]*$)") flag++;
  # Cat6k: 12.2(33)SXI2 onwards (note the '2' at the end)
  else if (tolower(model) =~ "^cat6k($|[^0-9])" && version =~ "^12\.2\(33\)SXI([2-9]|[1-9][0-9])($|[^0-9])") flag++;
}

if (get_kb_item("Host/local_checks_enabled") && flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"ethernet cfm", string:buf)) flag = 1;
  }
  else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCuq93406' +
      '\n  Installed release : ' + version +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
