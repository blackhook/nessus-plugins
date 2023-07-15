#TRUSTED 8308831e937278c84099ca71e52da2adac30250a33e3cd3e27d11316d6302fb4d2992f96c9ff4ed45f64c22e9fb7b6251fc407c508afc15214a162d4f2f9ea83d555813d2fe044ca95128e49f460f3ecca60ad7faa0dda641be7735e1d7cf326c8093d43e0ff2939c05ef9021d99462dfc45b3edcdc58cd1bb454c8da6b18ab0d34f7ce09ca6a023a0d022887de49d50ba058138c9671cd823a5446b81992c4366af08d8c992927c47733653d9462f06b2770e6e65fe1d0c4110fa1a1d52bf368f621100955804ee5445f26e8f0eaaee190a92f79a6a77e780647072f4904caa805165296de463e070ae07c01abfdbe91e7f5a43a9f458affa485c4d32a7b4862d52152c624ad2a6d843943e09e08ceb03396dc26086adb1f6e608d3e1e4f9337bd84cbd44efbed42b9e096536f5c8d66c6239ec35eda3bc89d66724a2dfe86a0f0108ea4e3fa6ee7e851b7f0b4e27f6c5ec57737cfaeede2759b98b64c508e5c04462173a6b21cf69bc78c8d97f47d662a7cf2f05d031d1cdb3ac6ca1990a061abb9c738aacfed72db6514b80c520badf40ac3fbd5cee6af2a855735193bf0131c5edd6d915787be09e90852cb3da036af2ab8d17206cdff615a51c127c5b1915b91f0ce9755ef78bf0f3aeafb63c74aec3d213fa250d2812dd6f4414ceb87f560707b9ca57c3ace9c48335b0f97058fb7a3b767cbd879a50eb888c4e19c688
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(55435);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/05");

  script_name(english:"Dropbox Installed (Mac OS X)");
  script_summary(english:"Gets Dropbox version from Info.plist");

  script_set_attribute(
    attribute:"synopsis",
    value:"There is a file synchronization application on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Dropbox is installed on the remote Mac OS X host.  Dropbox is an
application for storing and synchronizing files between computers,
possibly outside the organization."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.dropbox.com/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Ensure that use of this software agrees with your organization's
acceptable use and security policies."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dropbox:dropbox");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


kb_base = "MacOSX/Dropbox";


plist = "/Applications/Dropbox.app/Contents/Info.plist";
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) exit(0, "Dropbox does not appear to be installed.");
set_kb_item(name:kb_base+"/Installed", value:TRUE);

if (ereg(pattern:"^Dropbox ", string:version)) version = version - "Dropbox ";
if (version !~ "^[0-9]") exit(1, "The Dropbox version does not look valid (" + version + ").");
set_kb_item(name:kb_base+"/Version", value:version);

if (report_verbosity > 0)
{
  report = 
    '\n  Path    : /Applications/Dropbox.app' +
    '\n  Version : ' + version + '\n';
  security_note(port:0, extra:report);
}
else security_note(0);
