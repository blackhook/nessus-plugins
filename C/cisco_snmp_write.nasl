#TRUSTED 7564fa608c79bf81df6297063246e0b087a002b3e9778d74e4cd32b3f88b57b32f060b725a9a783f34df1d6b6eee99597f562766fbc2a41aac91105785a098482c8114352c27ab7a279d9f80c518fa4321d86891390d085c85736f36de4e6c4a80f8a4c9a736c56d796bd7765578c216ea0ad208acc1ff829390132bb8142d7644c153819efbb4a01a5a943856e405acb7cb09fed4da5a47366efe71fbe0ab80ef5fa8df63cb8528a1660124ccb2d52f8995e105dd01defcd5590066442cf3e9b471bf32694fd049b3abbc78152a1122a94ffd67b9d53307378b1a07fbb557bc4d77cf9bd5d582432476d1a00c78b8faa98e9ce68f59e26aae3c243a549ef3be95757e2e7af4e8b8258aac5a17d38b6e78266cf842a4f865a9fa60971acc25fdc9ed3d7492486e2dddc0d3777372b3e9d1baba2517855ecdac238b362958e7967b6aabe825d02588ebb837a034a858449c0a820e9d6c1c54096e6179f6f5f636d0cb396b20622cf2d181e033d19c0f3581b06a8a340b2c142db48bbc3d589c2bfad12f8f9a9123db71c7885da3301727905a51be01fe9d1d3674b4b6c5fdee954f476ee2a2069ab617fafdeaa7358a511ff60d8ced7df9d5a43d49856adf58c5ff190395c67d6a861802b6a637845f6c8c544cc96aa30e80b71056e0c39d37e7778dcdc3cdfea87c6d141d5a96c7c7b2f6fcc21cdf241e72262c2704c31396f1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109118);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_name(english:"Cisco IOS SNMP Community string write privileges.");
  script_summary(english:"Checks the IOS configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is has a SNMP community string with write privileges.");
  script_set_attribute(attribute:"description", value:
"According to its configuration, the Cisco IOS on the remote device
has a SNMP community string with write access. This could allow remote
configuration of the device, including copying and overwriting the
running-config.");
  script_set_attribute(attribute:"solution", value:
"Ensure this acocunt is supposed to have write access and that only
the expected MIBs are enabled on the SNMP server.");
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

get_kb_item_or_exit("Host/Cisco/IOS/Version");
port = get_kb_item("Host/Cisco/IOS/Port");

communities = NULL;

if (get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_snmp", "show running-config | include snmp");
  if (check_cisco_result(buf))
  {
    lines = split(buf, sep:'\n');
    foreach line (lines)
    {
       match = pregmatch(multiline:TRUE, pattern:"snmp-server community ([A-z]+) RW", string:line);
       if (!isnull(match))
       {
         communities += '    - ' + san_str(str:match[1]) + '\n';
       }
    }
  }
  else if (cisco_needs_enable(buf)) exit(0, "Enable credentials were not provided.");
}

if (communities)
{
  report = '\n  The following communities have write access:\n' + communities;
  security_report_v4(
    port     : port,
    severity : SECURITY_NOTE,
    extra    : report
  );
}
else audit(AUDIT_HOST_NOT, "affected");
