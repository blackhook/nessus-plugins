#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1084-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52580);
  script_version("1.12");
  script_cvs_date("Date: 2019/09/19 12:54:26");

  script_cve_id("CVE-2011-1002");
  script_bugtraq_id(46446);
  script_xref(name:"USN", value:"1084-1");

  script_name(english:"Ubuntu 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : avahi vulnerability (USN-1084-1)");
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
"It was discovered that Avahi incorrectly handled empty UDP packets. A
remote attacker could send a specially crafted packet and cause Avahi
to hang, resulting in a denial of service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1084-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-autoipd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-discover");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-dnsconfd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-ui-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-client-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-client3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-common-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-common-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-common3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-compat-howl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-compat-howl0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-compat-libdnssd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-compat-libdnssd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-core-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-core5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-core6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-core7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-glib1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-gobject-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-gobject0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-qt3-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-qt3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-qt4-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-qt4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-ui-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-ui0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-avahi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2019 Canonical, Inc. / NASL script (C) 2011-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
release = chomp(release);
if (! preg(pattern:"^(8\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"avahi-autoipd", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"avahi-daemon", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"avahi-dbg", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"avahi-discover", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"avahi-dnsconfd", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"avahi-utils", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-client-dev", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-client3", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-common-data", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-common-dev", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-common3", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-compat-howl-dev", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-compat-howl0", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-compat-libdnssd-dev", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-compat-libdnssd1", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-core-dev", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-core5", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-glib-dev", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-glib1", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-gobject-dev", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-gobject0", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-qt3-1", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-qt3-dev", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-qt4-1", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-qt4-dev", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-ui-dev", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavahi-ui0", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-avahi", pkgver:"0.6.22-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"avahi-autoipd", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"avahi-daemon", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"avahi-dbg", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"avahi-discover", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"avahi-dnsconfd", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"avahi-ui-utils", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"avahi-utils", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavahi-client-dev", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavahi-client3", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavahi-common-data", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavahi-common-dev", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavahi-common3", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavahi-compat-howl-dev", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavahi-compat-howl0", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavahi-compat-libdnssd-dev", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavahi-compat-libdnssd1", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavahi-core-dev", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavahi-core6", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavahi-glib-dev", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavahi-glib1", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavahi-gobject-dev", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavahi-gobject0", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavahi-qt3-1", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavahi-qt3-dev", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavahi-qt4-1", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavahi-qt4-dev", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavahi-ui-dev", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavahi-ui0", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"python-avahi", pkgver:"0.6.25-1ubuntu5.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"avahi-autoipd", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"avahi-daemon", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"avahi-dbg", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"avahi-discover", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"avahi-dnsconfd", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"avahi-ui-utils", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"avahi-utils", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libavahi-client-dev", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libavahi-client3", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libavahi-common-data", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libavahi-common-dev", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libavahi-common3", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libavahi-compat-howl-dev", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libavahi-compat-howl0", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libavahi-compat-libdnssd-dev", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libavahi-compat-libdnssd1", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libavahi-core-dev", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libavahi-core6", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libavahi-glib-dev", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libavahi-glib1", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libavahi-gobject-dev", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libavahi-gobject0", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libavahi-qt3-1", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libavahi-qt3-dev", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libavahi-qt4-1", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libavahi-qt4-dev", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libavahi-ui-dev", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libavahi-ui0", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"python-avahi", pkgver:"0.6.25-1ubuntu6.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"avahi", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"avahi-autoipd", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"avahi-daemon", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"avahi-dbg", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"avahi-discover", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"avahi-dnsconfd", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"avahi-ui-utils", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"avahi-utils", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libavahi-client-dev", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libavahi-client3", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libavahi-common-data", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libavahi-common-dev", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libavahi-common3", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libavahi-compat-libdnssd-dev", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libavahi-compat-libdnssd1", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libavahi-core-dev", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libavahi-core7", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libavahi-glib-dev", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libavahi-glib1", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libavahi-gobject-dev", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libavahi-gobject0", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libavahi-qt3-1", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libavahi-qt3-dev", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libavahi-qt4-1", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libavahi-qt4-dev", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libavahi-ui-dev", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libavahi-ui0", pkgver:"0.6.27-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"python-avahi", pkgver:"0.6.27-2ubuntu3.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avahi / avahi-autoipd / avahi-daemon / avahi-dbg / avahi-discover / etc");
}
