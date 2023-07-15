#%NASL_MIN_LEVEL 70300

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133090);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-8960", "CVE-2019-8961");
  script_xref(name:"TRA", value:"TRA-2019-49");

  script_name(english:"Flexera FlexNet Publisher lmadmin < 11.16.5.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A licensing application running on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Flexera FlexNet Publisher license server manager running on the
remote host is affected by multiple vulnerabilities : 

  - A denial of service (DoS) vulnerability exists in lmadmin due to
    improper handling of message fragments. An unauthenticated,
    remote attacker can exploit this issue, via a series of specially
    crafted messages, to cause the process to terminate. 
    (CVE-2019-8960)

  - A denial of service (DoS) vulnerability exists in lmadmin due to
    stack exhaustion when receiving message fragments. An
    unauthenticated, remote attacker can exploit this issue, via a
    series of specially crafted messages, to cause the process to
    terminate. (CVE-2019-8961)");
  # https://community.flexera.com/t5/FlexNet-Publisher-Knowledge-Base/CVE-2019-8960-remediated-in-FlexNet-Publisher/ta-p/124598
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53057bf9");
  # https://community.flexera.com/t5/FlexNet-Publisher-Knowledge-Base/CVE-2019-8961-remediated-in-FlexNet-Publisher/ta-p/124601
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b43c22ce");
  script_set_attribute(attribute:"solution", value:
"Upgrade to FlexNet Publisher 11.16.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8960");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:flexerasoftware:flexnet_publisher");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("flexnet_publisher_detection.nbin");
  script_require_keys("Services/flexnet_publisher");

  exit(0);
}

include('audit.inc');
include('byte_func.inc');
include('global_settings.inc');
include('misc_func.inc');
include('dump.inc');
include('spad_log_func.inc');

function save_kbs(lm, port)
{
  set_kb_item(name:'flexnet_publisher/' + lm, value:TRUE);
  set_kb_item(name:'flexnet_publisher/' + lm + '/' + port, value:TRUE);
  set_kb_item(name:'flexnet_publisher/' + port, value:lm);
}

port = get_service(svc:'flexnet_publisher', default:27000, exit_on_fail:TRUE);
soc = open_sock_tcp(port);
if(! soc) audit(AUDIT_SOCK_FAIL, port);

# FLEX_MSG_HELLO with 'communication revision' 0x7f splitted into 2 msg fragments
frag1 = raw_string(
  0x2F, 0x6A, 0x1E, 0xBE, 0x00, 0x15, 0x01, 0x02,
  0x00, 0x00, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x01, 0x01
);

frag2 = raw_string(
  0x2F, 0xB7, 0x07, 0x14, 0x00, 0x24, 0x01, 0x02,
  0x00, 0x00, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x7F, 0x0B, 0x10, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xD2, 0x00,
  0x00, 0x00, 0x00, 0x00
);

req = frag1 + frag2;

# Log requests and responses for debugging
spad_log(message:'request: \n' + hexdump(ddata:req));
send(socket:soc, data:req);

res = recv(socket:soc, length:0x100);
close(soc);
if(isnull(res)) audit(AUDIT_RESP_NOT, port);

spad_log(message:'response: \n' + hexdump(ddata:res));

# Patched lmadmin does not seem to support message fragmentation.
# It sees two malformed messages. It returns a LM_WHAT (0x57).
#
# 0x00:  57 57 00 00 00 00 00 00 00 00 00 00 00 00 00 00    WW..............
# 0x10:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
# *
# 0x90:  00 00 00
if(strlen(res) == 0x93 && res[0] == '\x57')
{
  # lmgrd is not affected. It supports message fragmentation, but
  # it uses a loop (instead of recursion) to read msg fragments.
  # When seeing a higher comm revision in FLEX_MSG_HELLO, lmgrd
  # returns a LM_WHAT msg with error code -83 
  # (Server FLEXlm version older than client's).
  #
  # 0x00:  57 EF 2D 38 33 00 00 00 00 00 00 00 00 00 00 00    W.-83...........
  # 0x10:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
  # *
  # 0x90:  00 00 00
  # 
  if(substr(res,2,4) == '-83')
    lm = 'lmgrd';
  else
    lm = 'lmadmin';

  save_kbs(port:port, lm:lm);
  audit(AUDIT_LISTEN_NOT_VULN, 'Flexnet Publisher (' + lm + ')', port);
}
# Vulerable lmadmin supports message fragmentation.
# It returns a 0x93-byte LM_OK (0x4F).
#
# 0x00:  4F FA 31 31 00 00 00 00 00 00 00 00 00 31 36 00    O.11.........16.
# 0x10:  00 00 00 00 00 00 00 00 20 31 00 00 00 00 00 00    ........ 1......
# 0x20:  00 00 00 00 34 00 00 00 00 00 00 00 00 00 00 77    ....4..........w
# 0x30:  32 6B 31 32 72 32 2D 76 6D 32 00 00 00 00 00 00    2k12r2-vm2......
# 0x40:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
# *
# 0x90:  00 00 00
else if (strlen(res) == 0x93 && res[0] == '\x4F')
{
  save_kbs(port:port, lm:'lmadmin');
  security_report_v4(port: port, severity: SECURITY_WARNING);
}
else
  audit(AUDIT_RESP_BAD, port, 'a fragmented FLEX_MSG_HELLO message. Response: \n' + hexdump(ddata:res));
