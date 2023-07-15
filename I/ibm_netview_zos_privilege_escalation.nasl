#TRUSTED 8be0b8876a7c7e28db30d2e7dbbee6b7f01f56e1e3bf7038da428f71a308c48db4e66417026d0475e022450cbeb04ba4bf2091505a4a982b7a13d532522d6b2d4a72551bf8b8eb43eaeba8d138cfd311a9416786aec9f0080897c337a29310bfe52f7dbacb920c17c0dd7a85bd17f948ea619e37b1b6c2eaba6781ade41d3b095bb65101e6317625d49ccc0eaf8ec27966fdabb4934a99184b29ad7312cf76ef500fdf352839f749b85c61252199040654929c6195ccdd3987643925f9dc9356889a17046d8d35dd7ab1d852d6765fd21c6554f0c8c955209eb7f07da52d89a4e39264a109aada473de0247e9c059c0d6ff79f3b6a181642a3f43c30a67bd9319c42a7b3d6d4d1cb8e86f4cad3a91c3e597a6ff1a3150f10eef8d4c9d68400ac8ed1c8f773745d87ce5585707ffe296999d0fc7e1c85a193f36c9f3c190b943af5d569ea8721a683b93dcef6d121767715512c8c0df8f1970e200c9fed1a8fa6b62fe191c1f61aeea1c346e7bff36d73ed18c44693e1133dcd4b2ee83b937b797e9f4b0776b8ffb962213abd9e03c19c95bec4f141112d2dda15bd91e234de8c153259d9d3508857ad91b1f34ced8d621d8c178affef49a82fcc603e89e28347a604850330d942ce056dc70eaef10faf3c23a2cca40154885826070dbf66302f148088bfa64218f36c5a71ac62645ce75efd43e381857ab05551a751fac1fb92
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70173);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2019/09/24");

  script_cve_id("CVE-2012-5951");
  script_bugtraq_id(57036);

  script_name(english:"IBM Tivoli NetView for z/OS Privilege Escalation");
  script_summary(english:"Checks NetView version over telnet.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host may be running software with a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to have IBM Tivoli NetView installed that is
affected by a privilege escalation vulnerability. A Unix System
Services authenticated attacker may be able to gain the privileges of
the NetView application.

Note that Nessus has not tested for the issues, but instead has relied
only on the detected version number. Nessus is unable to determine if
the patches for this vulnerability are installed as it does not change
this detected version number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21621163");
  script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20130215104605/http://xforce.iss.net/xforce/xfdb/80643");
  script_set_attribute(attribute:"solution", value:"Updates are available from the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_netview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2019 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/telnet", 23);
  script_require_keys("Secret/ClearTextAuth/login", "Secret/ClearTextAuth/pass");
  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");
include("telnet_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

login = get_kb_item_or_exit("Secret/ClearTextAuth/login");
password = get_kb_item_or_exit("Secret/ClearTextAuth/pass");

command = "grep VRM /usr/local/Tivoli/bin/generic_unix/TDS/client/lib/nmc.properties";
version_pattern = "=([0-9.]+)";

affected = make_list(
  "1.4",
  "5.1",
  "5.2",
  "5.3",
  "5.4",
  "6.1"
);

port = get_service(svc:"telnet", default:23, exit_on_fail:TRUE);

if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

res = telnet_negotiate(socket:soc);
res += recv_until(socket:soc, pattern:"login:");
if (isnull(res))
{
  close(soc);
  audit(AUDIT_NO_BANNER, port);
}

send(socket:soc, data:login + '\r\n');
res = recv_until(socket:soc, pattern:"Password:");
if (isnull(res))
{
  close(soc);
  audit(AUDIT_NO_BANNER, port);
}

send(socket:soc, data:password + '\r\n');
res = recv_until(socket:soc, pattern:"(\$|#|>) ");
if (isnull(res))
{
  close(soc);
  audit(AUDIT_NO_BANNER, port);
}

send(socket:soc, data:command + '\r\n');
res = recv_until(socket:soc, pattern:"(\$|#|>) ");
if (isnull(res))
{
  close(soc);
  audit(AUDIT_NOT_INST, "IBM Tivoli NetView for z/OS");
}

version = eregmatch(pattern:version_pattern, string:res);
version = version[1];

if (isnull(version))
  audit(AUDIT_NOT_INST, "IBM Tivoli NetView for z/OS");

report = "";

foreach vuln_ver (affected)
{
  if (ver_compare(ver:version, fix:vuln_ver, strict:FALSE) == 0)
  {
    report += "Version detected: " + version + '\n';
  }
}

if (report == "")
  audit(AUDIT_INST_VER_NOT_VULN, "IBM Tivoli NetView for z/OS", version);

if (report_verbosity > 0)
  security_hole(port:port, extra:report);
else
  security_hole(port:port);
