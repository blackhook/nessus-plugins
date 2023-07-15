#TRUSTED 7c05078831b498422a69fbcb5e60a4aecd81b37a3a8bf65101c86bee460a48814873316728f5df270b8f0051793eb9275ae8670cbb0c42923ede5b705d1b7b1f319ebb14f5f912c3f455233792077e7adaa1e31522e35a63d21e46aa65e3aaa73a43cee7f367e9e9d756007896375845092f50d205b7c9a0403e04cff1afc495a229eb43d04cd9e7c04843f5f95d600a493380a3c2662b6ec0b91c4049de624ab5079408ee78c2187aa1f092e42ff7cca6818d79dbf70dbaf7630ef62908e5d43225ab374cd212f92da27645a70da2dc940a2e5d24e4f4602d3561310a5952e3b492ea8d97e86c497fb3410f69dd9726326d799c1e49ce307c0913c7bd1fe6901054f995e5151db98393e54f99131c1858f54e73df8b4644f18df2b27d4be41a7baed509f7ec4dbc50ba8017155a4d44ce207e8c65e056ffcbbce1c708d85056a30784fbc8c0a5e4b5a9d7d406033de788ef0fc2b53bbe0d01f52bd00b8278957c61a00b56872be5b79cea4c9ee5069b73269d4c125fb201fdc35b04632638fe949492d16a299cfd38645ac8dc2b0bdcc6b31b7b6115cda938f968f6a72418a38ad663a13349077f81580c599f58a3420ee3b37fc08e1e14ee03cececcc86699c9519ae071edcfbab10bf4db184775125aea6c209a9d05c10238acd5ab71de8ceb39dde02da0cc530b2fd590586702bae6235d481e6167573c3070379879de1e
#TRUST-RSA-SHA256 6506f2fe925bf698a21ef4d1bd231e1ff8de0e2a75d1572b686e6b36970e4284968fee9d5b620764927fea36db2070a0032e71f2f8fce9618b91034537b39c2760f2b3b6678fd599e34d01363ee991f6608986f5886a9917c443a9cfb9026707bcc18bb6d3da044f69635d90088b2a725b66e451873426958d2ac2a345d91ef8c1f98dd18e37b4c6c77d340a37cab169f20c4e1f8336ca1c7a0304f8e13f0add12c6e7a798367443d5de6ca28d32e800df5962737456197488a7d0df1e9b8fb4623825e3e86c6bd4b11c2fcb4a12083eacef256bca7019f2f413831be7e08a7dfbe1b6ff400b3f9a1bec622ce1ae6da6b199c125c3a662ed88e52c2bb868b0a23cd4cde672764bce6b6fe0a712acb5cbf50f85dc0b003b1f0f5b888b13fd3c03a284768ac56b9fb7348391cf4cc39b028039da615d7596a446ddc7a7eefa509d82034f2706a2914ca61bc3837ec41dde712eb2e214128d6531b084d528253d6bd865c6c98342822e1b7486f6719d6e17f5ca73878f50bdf4da2a940ba43790f1252ed67b83ca77029bad923f122cd7665bb1f7ca5a7f21895b80feffa015f56b9277fd31513f41079e5c20f5b2cda6f334a7d01e7bb33cb60aadf6420622106a5075970507348a5a0478aa41ecd737a48da0f320ac449b1d77b90d46595b0e1da55b634450bd7b394dca6b2d27a165e20970541fa5bd54fae8ffb352bec54730
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72261);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/21");

  script_cve_id("CVE-2013-4128", "CVE-2013-4213");
  script_bugtraq_id(61739, 61742);
  script_xref(name:"RHSA", value:"2013:1152");

  script_name(english:"Red Hat JBoss Enterprise Application Platform 6.1.0 Security Update (RHSA-2013:1152)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of JBoss Enterprise Application Platform running on the
remote system is vulnerable to the following issues:

  - A flaw in the way authenticated connections are cached
    on the server by remote-naming could allow a remote
    attacker to log in as another user without knowing
    their password. (CVE-2013-4128)

  - A flaw in the way connections for remote EJB
    invocations via the EJB client API are cached on the
    server could allow a remote attacker to use an EJB
    client to log in as another user without knowing their
    password. (CVE-2013-4213)");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-4128.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-4213.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate JBoss Enterprise Application Platform 6.1.0
security update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4128");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_application_platform:6.1.0");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "jboss_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("local_detection_nix.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

var buf = NULL;
var cmd = NULL;
var cmd_template = NULL;
var found = NULL;
var full_path = NULL;
var info = NULL;
var install = NULL;
var installs = NULL;
var matches = NULL;
var path = NULL;
var release = NULL;
var report = NULL;
var s = NULL;
var sock_g = NULL;
var ver = NULL;

# We are only interested in Red Hat systems
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
installs = get_kb_list_or_exit("Host/JBoss/EAP");

# We may support other protocols here
if ( islocalhost() )
{
 if ( ! defined_func("pread") ) exit(1, "'pread()' is not defined.");
 info_t = INFO_LOCAL;
}
else
{
 sock_g = ssh_open_connection();
 if (! sock_g) exit(1, "ssh_open_connection() failed.");
 info_t = INFO_SSH;
}

info = "";
jboss = 0;
if(!isnull(installs)) jboss = 1;

foreach install (make_list(installs))
{
  matches = pregmatch(string:install, pattern:"([^:]+):(.*)");

  if (!isnull(matches))
  {
    ver = matches[1];
    path = matches[2];

    # check for install version = 6.1.0
    if (ver =~ "^6.1.0([^0-9]|$)")
    {
      found = 0;

      full_path = path + 'modules/system/layers/base/org/jboss/remote-naming/'
        + 'main/jboss-remote-naming-1.0.6.Final-redhat-2.jar';
      cmd_template = 'test -f "$1$" && echo FOUND';
      buf = ldnix::run_cmd_template_wrapper(template: cmd_template, args: [full_path]);

      if ( (buf) && ("FOUND" >< buf) )
        found = 1;

      full_path = path + 'modules/system/layers/base/org/jboss/ejb-client/main/'
        + 'jboss-ejb-client-1.0.21.Final-redhat-1.jar';
      cmd = 'test -f "$1$" && echo FOUND';
      buf = ldnix::run_cmd_template_wrapper(template: cmd_template, args: [full_path]);

      if ( (buf) && ("FOUND" >< buf) )
        found = 1;

      if (found)
      {
        info += '\n' + '  Path    : ' + path+ '\n';
        info += '  Version : ' + ver + '\n';
      }
    }
  }
}
if (info_t == INFO_SSH) ssh_close_connection();

# Report what we found.
if (!info) audit(AUDIT_HOST_NOT, "affected");

if (max_index(split(info)) > 3) s = 's of JBoss Enterprise Application Platform are';
else s = ' of JBoss Enterprise Application Platform is';

report =
  '\n' +
  'The following instance'+s+' out of date and\nshould be patched or upgraded as appropriate :\n' +
  info;

security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);

