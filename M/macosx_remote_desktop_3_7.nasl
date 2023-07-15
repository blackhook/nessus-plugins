#TRUSTED 021d073a96db9506b657e176d340e03a2213db945c465f90e4e7c796bea1ef5a0035963a533e6e5a4d08f9bb968887cec989715fd1482283986e2e3dd458f852ea56d913f1fa8bac24d21eb6ba5faa18af1a862ec9c27973acd02ba6570314b4f1c8056809037f464a51841acb91c4e7e8e06de68e4bd50f2ccf803d6808c43b348b598e5f0b529f6428cec57009eb940208bb89ffa127baed5447b704fa1af0b1d8b7e7ba40c9e094db5581db960c4043bc157d09daf9afb3eee613978468fb8cb369b709969c7bee04ef47a87f4959bae31d375a20bbd50e1dd2f21480ae957920759da018ff1d4983d71b868326475b968d4c4083e5b97a5c444489f110afcdd7e561c32518a08021081c0077987bed65f2bf737b14425ca7313d26b2f0023a43c223e552c87dc64a6423a3846d592d654e9717c3032dc2dc943e7fc49b65b8ba82ff7253af65388d8f23f12d83062de6985d99125066fefcb185acc9b24fb80ac7a6537fa2bf75d39dddbfe3606520bff1676c8b476e690c1b33234a8f7665020ac862d40e0f25ae33823118596b2c84a43758c8f31a310f8a5d34ab9f84e72c7803a9b7f6dd39f22eecf4359e5c28c5d8157684b1fd71823a08698cf3655a3a685a582ec2b91b22737b2b8053db197590819a2c69e8e421c2b50c28ba8affe44d66e4a4e5b612c9162cadf032889e6423fd36dc2eb0949f4baa10023891
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(70609);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2013-5135", "CVE-2013-5136", "CVE-2013-5229");
  script_bugtraq_id(63284, 63286);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-10-22-6");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-10-22-7");

  script_name(english:"Apple Remote Desktop < 3.5.4 / 3.7 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Reads version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:
"The Mac OS X host has a remote management application that is
potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Apple Remote Desktop install on the
remote host is earlier than 3.5.4 / 3.7.  As such, it is potentially
affected the following vulnerabilities :

  - A format string vulnerability exists in Remote 
    Desktop's handling of a VNC username. (CVE-2013-5135)

  - An information disclosure vulnerability exists because
    Remote Desktop may use password authentication without
    warning that the connection would be encrypted if a
    third-party VNC server supports certain authentication
    types. Note that this does not affect installs of
    version 3.5.x or earlier. (CVE_2013-5136)

  - An authentication bypass vulnerability exists due to a
    flaw in the full-screen feature that is triggered when
    handling text entered in the dialog box upon recovering 
    from sleep mode with a remote connection alive. A local
    attacker can exploit this to bypass intended access
    restrictions. (CVE-2013-5229)");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5997");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5998");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Oct/msg00007.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Oct/msg00008.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Remote Desktop 3.5.4 / 3.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-5135");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_remote_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/MacOSX/Version"))audit(AUDIT_HOST_NOT, "running Mac OS X");

plist = '/System/Library/CoreServices/RemoteManagement/AppleVNCServer.bundle/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) audit(AUDIT_NOT_INST, "Apple Remote Desktop Client");

if (version !~ "^[0-9]") exit(1, "The version does not look valid (" + version + ").");


if (
  ereg(pattern:"^3\.[0-4]($|[^0-9])", string:version) ||
  ereg(pattern:"^3\.5\.[0-3]($|[^0-9])", string:version) ||
  ereg(pattern:"^3\.6(\.[0-9])?($|[^0-9.])", string:version)
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 3.5.4 / 3.7' +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Apple Remote Desktop Client", version);
