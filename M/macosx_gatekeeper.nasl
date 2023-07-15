#TRUSTED 296709ab54160f66e8c3530dd66548d95813b25daa3262e86589a90029308e43659dadaef287e4f8e92a4f353da8fe701eab4742e3561c4da4b43f6927c0324e1fbd744498c82b18aaf38c07ff75f0b6b9524f8ba7a2dedcc1d7bdfe047fb8bdc76ed87d0bb4f17e87b1fe1cbf88d59032ca71c229afc5f2f8a207c08572c1d3d31700581734c64347dc241daf8bf5df15b32e8e78b9c2384bdcb3f4a18f0b46073ed2db08f0945c604f697e5407a089ff3d6154f50d0dba94f638613ae6af39f15da29e76a00b16291ef46ba652e399cd0b5791da16803bf090a9835b46306a7a4af722106acf0b6d552c284c580292a593d1d8cbc827cd06872950991873b8edce145fe365eb177e74c24ce2f24dd575b4c78b7eda6e29be0e1c14194f31032ec15f1bb2a9830498a3e7d3e4b18f73d5293d90814a5e4a39618e058aad2e23c73e49526005665d83d8388a9d78645d54d66eaf13dce4035644fdc60bba67a8f73fcc4032ceefc65ce980addc736d4a8b12c6fd3c9a26b0c2cf8c1c25bf120b1dd1d86addcf3574d719874b0c71e29ec51e748f77cbb2c89ce0a8194faf5bb8e6bf872680de69ff85fc9faabeb2d6e2e3beeb9b501d1df4514181a6c7b31f4b16ea309d8121d9c943400c31eb61983d376662c83f123b1f97bc74b3cd7e49172dc6618c7e9bf64e0c7a0155d360e48d511e7c1d14424f7ee24d67ca6e5864bf
#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(89924);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_name(english:"Mac OS X Gatekeeper Disabled");
  script_summary(english:"Checks that Gatekeeper is enabled.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has Gatekeeper disabled.");
  script_set_attribute(attribute:"description", value:
"Mac OS X Gatekeeper, a protection service that guards against
untrusted software, is disabled on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-ca/HT202491");
  script_set_attribute(attribute:"solution", value:
"Ensure that this use of Gatekeeper is in accordance with your security
policy.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os)
  audit(AUDIT_OS_NOT, "Mac OS X");

extract = eregmatch(pattern:"^Mac OS X ([\d.]+)$", string:os);
if (!isnull(extract))
  version = extract[1];
else
  exit(1, "Error extracting Mac OS X version.");

# Gatekeeper arrived in OS X 10.7.5
 # audit-trail:success: The remote host's OS is Mac OS X 10.7.5, which is required for Gatekeeper, not Mac OS X 10.7.4.
if (ver_compare(ver:version, fix:"10.7.5", strict:FALSE) < 0)
  audit(AUDIT_OS_NOT, "Mac OS X 10.7.5, which is required for Gatekeeper", os);

cmd = 'spctl --status';

res = exec_cmd(cmd:cmd);

if ( "assessments enabled" >!< res && "assessments disabled" >!< res)
  exit(1, "Unexpected output from '" + cmd + "'.");

if ( "assessments enabled" >< res )
{
  set_kb_item(name:"Host/MacOS/Gatekeeper/enabled", value:TRUE);
  exit(0, "Gatekeeper is enabled.");
}
else
{
  report = '\n  Mac OS X Gatekeeper is disabled. Ensure this is in accordance' +
           '\n  with your security policy.' +
           '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
  exit(0);
}
