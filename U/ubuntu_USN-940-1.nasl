#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-940-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46688);
  script_version("1.18");
  script_cvs_date("Date: 2019/09/19 12:54:26");

  script_cve_id("CVE-2007-5902", "CVE-2007-5971", "CVE-2007-5972", "CVE-2010-1320", "CVE-2010-1321");
  script_bugtraq_id(26750, 39599);
  script_xref(name:"USN", value:"940-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 9.04 / 9.10 : krb5 vulnerabilities (USN-940-1)");
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
"It was discovered that Kerberos did not correctly free memory in the
GSSAPI and kdb libraries. If a remote attacker were able to manipulate
an application using these libraries carefully, the service could
crash, leading to a denial of service. (Only Ubuntu 6.06 LTS was
affected.) (CVE-2007-5902, CVE-2007-5971, CVE-2007-5972)

Joel Johnson, Brian Almeida, and Shawn Emery discovered that Kerberos
did not correctly verify certain packet structures. An unauthenticated
remote attacker could send specially crafted traffic to cause the KDC
or kadmind services to crash, leading to a denial of service.
(CVE-2010-1320, CVE-2010-1321).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/940-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-admin-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-ftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kdc-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-rsh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-telnetd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgssapi-krb5-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgssrpc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libk5crypto3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5clnt6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5srv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdb5-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5support0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/20");
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
if (! preg(pattern:"^(6\.06|8\.04|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"krb5-admin-server", pkgver:"1.4.3-5ubuntu0.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-clients", pkgver:"1.4.3-5ubuntu0.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-doc", pkgver:"1.4.3-5ubuntu0.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-ftpd", pkgver:"1.4.3-5ubuntu0.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-kdc", pkgver:"1.4.3-5ubuntu0.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-rsh-server", pkgver:"1.4.3-5ubuntu0.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-telnetd", pkgver:"1.4.3-5ubuntu0.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-user", pkgver:"1.4.3-5ubuntu0.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkadm55", pkgver:"1.4.3-5ubuntu0.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkrb5-dev", pkgver:"1.4.3-5ubuntu0.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkrb53", pkgver:"1.4.3-5ubuntu0.11")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"krb5-admin-server", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"krb5-clients", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"krb5-doc", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"krb5-ftpd", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"krb5-kdc", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"krb5-pkinit", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"krb5-rsh-server", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"krb5-telnetd", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"krb5-user", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libkadm55", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libkrb5-dbg", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libkrb5-dev", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libkrb53", pkgver:"1.6.dfsg.3~beta1-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"krb5-admin-server", pkgver:"1.6.dfsg.4~beta1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"krb5-clients", pkgver:"1.6.dfsg.4~beta1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"krb5-doc", pkgver:"1.6.dfsg.4~beta1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"krb5-ftpd", pkgver:"1.6.dfsg.4~beta1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"krb5-kdc", pkgver:"1.6.dfsg.4~beta1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"krb5-kdc-ldap", pkgver:"1.6.dfsg.4~beta1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"krb5-pkinit", pkgver:"1.6.dfsg.4~beta1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"krb5-rsh-server", pkgver:"1.6.dfsg.4~beta1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"krb5-telnetd", pkgver:"1.6.dfsg.4~beta1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"krb5-user", pkgver:"1.6.dfsg.4~beta1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libkadm55", pkgver:"1.6.dfsg.4~beta1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libkrb5-dbg", pkgver:"1.6.dfsg.4~beta1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libkrb5-dev", pkgver:"1.6.dfsg.4~beta1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libkrb53", pkgver:"1.6.dfsg.4~beta1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-admin-server", pkgver:"1.7dfsg~beta3-1ubuntu0.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-clients", pkgver:"1.7dfsg~beta3-1ubuntu0.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-doc", pkgver:"1.7dfsg~beta3-1ubuntu0.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-ftpd", pkgver:"1.7dfsg~beta3-1ubuntu0.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-kdc", pkgver:"1.7dfsg~beta3-1ubuntu0.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-kdc-ldap", pkgver:"1.7dfsg~beta3-1ubuntu0.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-pkinit", pkgver:"1.7dfsg~beta3-1ubuntu0.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-rsh-server", pkgver:"1.7dfsg~beta3-1ubuntu0.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-telnetd", pkgver:"1.7dfsg~beta3-1ubuntu0.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"krb5-user", pkgver:"1.7dfsg~beta3-1ubuntu0.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libgssapi-krb5-2", pkgver:"1.7dfsg~beta3-1ubuntu0.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libgssrpc4", pkgver:"1.7dfsg~beta3-1ubuntu0.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libk5crypto3", pkgver:"1.7dfsg~beta3-1ubuntu0.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkadm5clnt6", pkgver:"1.7dfsg~beta3-1ubuntu0.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkadm5srv6", pkgver:"1.7dfsg~beta3-1ubuntu0.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkdb5-4", pkgver:"1.7dfsg~beta3-1ubuntu0.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkrb5-3", pkgver:"1.7dfsg~beta3-1ubuntu0.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkrb5-dbg", pkgver:"1.7dfsg~beta3-1ubuntu0.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkrb5-dev", pkgver:"1.7dfsg~beta3-1ubuntu0.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkrb5support0", pkgver:"1.7dfsg~beta3-1ubuntu0.6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-admin-server / krb5-clients / krb5-doc / krb5-ftpd / krb5-kdc / etc");
}
