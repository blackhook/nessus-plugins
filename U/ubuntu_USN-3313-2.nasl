#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2018/10/15.

include("compat.inc");

if (description)
{
  script_id(100667);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2017-0605");
  script_xref(name:"USN", value:"3313-2");

  script_name(english:"Ubuntu 16.04 LTS : linux-hwe vulnerability (USN-3313-2) (deprecated)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"CVE-2017-0605 was deemed 'Rejected', and withdrawn from the NIST
database as further investigation showed that it was not a true
security risk."
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.8-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.8-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.8-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017-2023 Canonical, Inc. / NASL script (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

exit(0, "This plugin has been deprecated.");

include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! ereg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.8.0-54-generic", pkgver:"4.8.0-54.57~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.8.0-54-generic-lpae", pkgver:"4.8.0-54.57~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.8.0-54-lowlatency", pkgver:"4.8.0-54.57~16.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-hwe-16.04", pkgver:"4.8.0.54.25")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-lpae-hwe-16.04", pkgver:"4.8.0.54.25")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-lowlatency-hwe-16.04", pkgver:"4.8.0.54.25")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.8-generic / linux-image-4.8-generic-lpae / etc");
}
