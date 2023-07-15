#TRUSTED b048a4a687f97c2f87d0dddb08eaca59ab4749662e40a958e1751f35d03b29edc43b84d7e8389b6f079df1cd63598b01c17e1d88f5f90dc85973ef3c28fc1fabd27ef6af8d78294316a3fa2c7a72068a1d13264d1fce1b874c70908f253f96d4d48dae4ff71772a0a000fc02db1b9cc83565294e7d33601a80b029807228dd063a5f19a3cbd34cf057f7baf3ee08fb783a0683cae349282851321f802e03f608b6bfdfa58997b0236e1d00fb5389f79bed998d03ad1ba4df50bf287f5ed1b22a1ed98353376644d015c3800c40780d941fc4445328626ce0b6105c124ef9b1c1007a70f01d00f9e53966f2ac484963ef086e197a9a78167ec030449c102f44f5598f1d6a5ac51bb1dc9e2a29c23dffaf8cc5922aeed2f5b33fe7fb4fde29ecf40e4ab20b45088f525e67e3ecc7402821148281beb19fbb2cce90d3c6a843fbc32776c78d58b52f6cc49315bd989d9ec30867834760361711a694a668626c440ab81f9938fdee016af20a938ec78a708a9883fa6f2b775c66f490c723cdb38983d89e52bab4e69e3b347d0d6069532622c2937b9772058592fdca39c012ca4797cded3225ad7e9170b6b7999e9f51355728ea45d99960dd7ab70b4d1e3915f9c18ec4c60177019e33547021d7710b41053422f1d16593b82f9bafaf96f58f4c2bf4e050df749f14e449b15493a050572335184dde780a664ad9a9d29bd357cbe6
#TRUST-RSA-SHA256 09dca59da9eeb61a769419c23a7bf4350d7e5163579c8fe8fa2836b5c3059ebf17e547e9266a1cb1317a045a4a9f02b6e3399e8c3b45078918ed768335d186196cbfdf7d7c1eb208dbd344d38dbe4aeae633d870d78d0c6560fd79d3a8479c6e2d217abff9b6379d477aac4b20ccb87fac704944c0e5a79ed47f678cf6f836e574a78168ca7820d541163001b7288c33c75a57153ea0725078eacaf538cb549bb889b10d6aaa42ced6109a8c2d686b0b7dd5b290ce12e5c61e8c0ca960afbe64c6f1b89cf0b140351005f0bba67ea1b04f9ea920731b9449af0859bb9213d12ea2f193b73bf434ec3771b3cffbf430325235535e00a7bdd5e329ef5627ac7ae2ae3080bb3cd3d4a6b116bacb303fa1526793f1d2eb683fca5860c1f0f524a258f2d37ca266ce99df100838c36060973421f3f1dd64fcded4b2c501d2bbbaeef85857cac4bc161e238d718fe820a0a094a90fb326be2939acb92b4efbcbaa8a59b6c07aa870b439adae266bc9d7112ff29ab91891f4fed6b6b26d1df1f57e1443ee0a80f72faeb6234ed7033cc9ec669bb216d12464b87da5a92fe503af35f18e04c98fe2b1dc4508fcd8bf371e541eaaec03c28a3f7ff92b1851d2594bbda164aff5d6cee7c3f4fbc980d8093d397d85634169b650daab9cf294409815c426e4f523efd5658d404d69e0df5b14aa4d7f071855e684d6ced17cc05accffc33af2
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(91457);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id("CVE-2016-3427");
  script_xref(name:"VMSA", value:"2016-0005");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"VMware vSphere Replication Oracle JRE JMX Deserialization RCE (VMSA-2016-0005)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is a virtualization appliance that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The VMware vSphere Replication running on the remote host is version
5.6.x prior to 5.6.0.6, 5.8.x prior to 5.8.1.2, 6.0.x prior to
6.0.0.3, or 6.1.x prior to 6.1.1. It is, therefore, affected by a
remote code execution vulnerability in the Oracle JRE JMX component
due to a flaw related to the deserialization of authentication
credentials. An unauthenticated, remote attacker can exploit this to
execute arbitrary code.

Note that vSphere Replication is only affected if its vCloud Tunneling
Agent is running, and it is not enabled by default.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2016-0005.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vSphere Replication version 5.6.0.6 / 5.8.1.2 /
6.0.0.3 / 6.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3427");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:vmware:vsphere_replication");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/VMware vSphere Replication/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");
include("telnet_func.inc");
include("misc_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

version = get_kb_item_or_exit("Host/VMware vSphere Replication/Version");
verui = get_kb_item_or_exit("Host/VMware vSphere Replication/VerUI");
build = get_kb_item_or_exit("Host/VMware vSphere Replication/Build");

fix = '';
vuln = FALSE;

if (version =~ '^5\\.6\\.' && int(build) < 3845873) fix = '5.6.0.6 Build 3845873';
else if (version =~ '^5\\.8\\.' && int(build) < 3845890) fix = '5.8.1.2 Build 3845890';
else if (version =~ '^6\\.0\\.' && int(build) < 3845888) fix = '6.0.0.3 Build 3845888';
else if (version =~ '^6\\.1\\.' && int(build) < 3849281) fix = '6.1.1 Build 3849281';

if (!empty(fix))
{
  sock_g = ssh_open_connection();
  if (! sock_g)
    audit(AUDIT_HOST_NOT, "able to connect via the provided SSH credentials.");
  info_t = INFO_SSH;

  line = info_send_cmd(cmd:"service vmware-vcd status");
  ssh_close_connection();

  if (
    "vmware-vcd-watchdog is running" >< line &&
    "vmware-vcd-cell is running" >< line
  )
  {
    vuln = TRUE;
  }
  else
    exit(0, "vCloud Tunneling Agent does not appear to be running on the VMware vSphere Replication appliance examined (Version " + verui + ").");

}

if (vuln)
{
  report =
    '\n  Installed version : ' + verui +
    '\n  Fixed version     : ' + fix +
    '\n';

   security_report_v4(
    extra    : report,
    port     : '0',
    severity : SECURITY_HOLE
  );
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'VMware vSphere Replication', verui);
