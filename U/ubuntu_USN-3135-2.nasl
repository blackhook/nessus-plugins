#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3135-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95371);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");
  script_xref(name:"USN", value:"3135-2");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS / 16.10 : gst-plugins-good0.10, gst-plugins-good1.0 vulnerability (USN-3135-2)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description",
    value:
"USN-3135-1 fixed a vulnerability in GStreamer Good Plugins. The
original security fix was incomplete. This update fixes the problem.

Chris Evans discovered that GStreamer Good Plugins did not correctly
handle malformed FLC movie files. If a user were tricked into opening
a crafted FLC movie file with a GStreamer application, an attacker
could cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking the program.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3135-2/"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Update the affected gstreamer0.10-plugins-good and / or
gstreamer1.0-plugins-good packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer0.10-plugins-good");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer1.0-plugins-good");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016-2023 Canonical, Inc. / NASL script (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
var release = chomp(release);
if (! preg(pattern:"^(12\.04|14\.04|16\.04|16\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04 / 16.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"gstreamer0.10-plugins-good", pkgver:"0.10.31-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"gstreamer0.10-plugins-good", pkgver:"0.10.31-3+nmu1ubuntu5.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"gstreamer1.0-plugins-good", pkgver:"1.2.4-1~ubuntu1.3")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"gstreamer1.0-plugins-good", pkgver:"1.8.2-1ubuntu0.3")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"gstreamer1.0-plugins-good", pkgver:"1.8.3-1ubuntu1.2")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer0.10-plugins-good / gstreamer1.0-plugins-good");
}
