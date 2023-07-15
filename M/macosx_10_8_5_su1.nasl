#TRUSTED 708630476f945f518e673ef7930bd895bdbe01a375a45905c6ba541a79eeba9c242e52fcab675d19723c7502bbcb5ad98bf999bc176a2aaf56721ebdd3e55ecab191d95e070bc68de73be76b08e5b130c503f9b31136ebbde7268188e8e0687157f91ab2b5642360e383567d990cd6f3bab0ffca8f402bacbdfe718facdeb3efb4631e4648a7e249e6eb61a0355a839c01616d2c46ee80a05baac4758c64acef68508668d9c1e5e1477a1d5283874e35404a79d74f089f6455e9bba2814d08d87158ea7a8f6577ef30935c162da431e79bc9b4ba72ebc50ffbd19ccf1f117d15dc86087e65522a5438f1aa8bdb9e64308773ecf2f22e0d65baacf2b13655f3ab22bc45cb751795ca9db68bce86a9cc8e674589a2d57a35bfe3ee479fa0d86f9195670af3e10108959ef10cbe73a0161e0cc3800c67b28732478dbf031ad84db9790fe59d90e36a74caf9154001cdc4b75a3c1b05323fec5cd020f0ee41a02c3e31a1ded14c90412272145c2c829a9c85ded2db6c4c3c4c7ca8f39186b5de403b5c459f474ce1333ce0fb3484e61a6d8009365af04b6d2819ed4e549f28f7782251d210ac7952dcba8750fa96863fbc5fa656ec94d37d301322576beb1e7ee6be70f3602cb40db41d9f0bebb8dd7d24af1372b478059b46552530c1b0d0df4894feb70fff669af9be2413f6212594c109be5f96d25341c7e2a794c72fab5bace7
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(70301);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2013-5163");
  script_bugtraq_id(62812);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-10-03-1");

  script_name(english:"Mac OS X 10.8 < 10.8.5 Supplemental Update");
  script_summary(english:"Check the version of Mac OS X");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X security update that fixes a
local security bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of Mac OS X 10.8 that is missing
the OS X v10.8.5 Supplemental Update.  This update fixes a logic issue
in verification of authentication credentials by Directory Services,
which could otherwise allow a local attacker to bypass password
validation."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5964");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Oct/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/528980/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Install the OS X v10.8.5 Supplemental Update.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 Tenable Network Security, Inc.");

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

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");
if (!ereg(pattern:"Mac OS X 10\.8([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.8");
if (!ereg(pattern:"Mac OS X 10\.8($|\.[0-5]([^0-9]|$))", string:os)) exit(0, "The remote host uses a version of Mac OS X Mountain Lion later than 10.8.5.");


# Get the product build version.
plist = "/System/Library/CoreServices/SystemVersion.plist";
cmd =
  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 ProductBuildVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
build = exec_cmd(cmd:cmd);
if (
  !strlen(build) ||
  build !~ "^12F[0-9]+$"
) exit(1, "Failed to extract the ProductBuildVersion from '"+plist+"'.");


if (build =~ "^12F([0-9]|[1-3][0-9]|4[0-4])$")
{
  if (report_verbosity > 0)
  {
    report = '\n  Product version                 : ' + os +
             '\n  Installed product build version : ' + build +
             '\n  Fixed product build version     : 12F45' +
             '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else exit(0, "The host has product build version "+build+" and is not affected.");
