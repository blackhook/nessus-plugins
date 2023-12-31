#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1011-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50411);
  script_version("1.18");
  script_cvs_date("Date: 2019/09/19 12:54:26");

  script_cve_id("CVE-2010-3765");
  script_bugtraq_id(44425);
  script_xref(name:"USN", value:"1011-2");

  script_name(english:"Ubuntu 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : thunderbird vulnerability (USN-1011-2)");
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
"USN-1011-1 fixed a vulnerability in Firefox. This update provides the
corresponding update for Thunderbird.

Morten Krakvik discovered a heap-based buffer overflow in Firefox. If
a user were tricked into navigating to a malicious site, an attacker
could cause a denial of service or possibly execute arbitrary code as
the user invoking the program.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1011-2/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox Interleaved document.write/appendChild Memory Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-gnome-support-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2019 Canonical, Inc. / NASL script (C) 2010-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (ubuntu_check(osver:"8.04", pkgname:"mozilla-thunderbird", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mozilla-thunderbird-dev", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"thunderbird", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"thunderbird-dev", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"thunderbird-gnome-support", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mozilla-thunderbird", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.9.10.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mozilla-thunderbird-dev", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.9.10.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"thunderbird", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.9.10.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"thunderbird-dev", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.9.10.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"thunderbird-gnome-support", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.9.10.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird", pkgver:"3.0.10+build1+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-dbg", pkgver:"3.0.10+build1+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-dev", pkgver:"3.0.10+build1+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-gnome-support", pkgver:"3.0.10+build1+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-gnome-support-dbg", pkgver:"3.0.10+build1+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"thunderbird", pkgver:"3.1.6+build1+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"thunderbird-dbg", pkgver:"3.1.6+build1+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"thunderbird-dev", pkgver:"3.1.6+build1+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"thunderbird-gnome-support", pkgver:"3.1.6+build1+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"thunderbird-gnome-support-dbg", pkgver:"3.1.6+build1+nobinonly-0ubuntu0.10.10.1")) flag++;

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
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla-thunderbird / mozilla-thunderbird-dev / thunderbird / etc");
}
