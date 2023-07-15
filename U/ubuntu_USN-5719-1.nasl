#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5719-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167234);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2022-21618",
    "CVE-2022-21619",
    "CVE-2022-21624",
    "CVE-2022-21626",
    "CVE-2022-21628",
    "CVE-2022-39399"
  );
  script_xref(name:"USN", value:"5719-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : OpenJDK vulnerabilities (USN-5719-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-5719-1 advisory.

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: JGSS). Supported versions that are affected are Oracle Java SE: 17.0.4.1, 19; Oracle GraalVM
    Enterprise Edition: 21.3.3 and 22.2.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via Kerberos to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to
    some of Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability
    applies to Java deployments, typically in clients running sandboxed Java Web Start applications or
    sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and
    rely on the Java sandbox for security. This vulnerability can also be exploited by using APIs in the
    specified Component, e.g., through a web service which supplies data to the APIs. (CVE-2022-21618)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Security). Supported versions that are affected are Oracle Java SE: 8u341, 8u345-perf,
    11.0.16.1, 17.0.4.1, 19; Oracle GraalVM Enterprise Edition: 20.3.7, 21.3.3 and 22.2.0. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can
    result in unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM
    Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run
    untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This
    vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service
    which supplies data to the APIs. (CVE-2022-21619)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: JNDI). Supported versions that are affected are Oracle Java SE: 8u341, 8u345-perf, 11.0.16.1,
    17.0.4.1, 19; Oracle GraalVM Enterprise Edition: 20.3.7, 21.3.3 and 22.2.0. Difficult to exploit
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition
    accessible data. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also
    be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to
    the APIs. (CVE-2022-21624)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Security). Supported versions that are affected are Oracle Java SE: 8u341, 8u345-perf,
    11.0.16.1; Oracle GraalVM Enterprise Edition: 20.3.7, 21.3.3 and 22.2.0. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTPS to compromise Oracle Java SE, Oracle GraalVM
    Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized ability to cause a
    partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM Enterprise Edition. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs.
    (CVE-2022-21626)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Lightweight HTTP Server). Supported versions that are affected are Oracle Java SE: 8u341,
    8u345-perf, 11.0.16.1, 17.0.4.1, 19; Oracle GraalVM Enterprise Edition: 20.3.7, 21.3.3 and 22.2.0. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM
    Enterprise Edition. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not
    apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed
    by an administrator). (CVE-2022-21628)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Networking). Supported versions that are affected are Oracle Java SE: 11.0.16.1, 17.0.4.1, 19;
    Oracle GraalVM Enterprise Edition: 20.3.7, 21.3.3 and 22.2.0. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Oracle Java SE, Oracle GraalVM
    Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized update, insert or
    delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2022-39399)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5719-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21618");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-17-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-19-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-19-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-19-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-19-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-19-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-19-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-19-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-source");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '22.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u352-ga-1~16.04'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u352-ga-1~16.04'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u352-ga-1~16.04'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u352-ga-1~16.04'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u352-ga-1~16.04'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-jamvm', 'pkgver': '8u352-ga-1~16.04'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u352-ga-1~16.04'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u352-ga-1~16.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.17+8-1ubuntu2~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.17+8-1ubuntu2~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.17+8-1ubuntu2~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.17+8-1ubuntu2~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.17+8-1ubuntu2~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.17+8-1ubuntu2~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.17+8-1ubuntu2~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.5+8-2ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.5+8-2ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.5+8-2ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.5+8-2ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.5+8-2ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.5+8-2ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.5+8-2ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u352-ga-1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u352-ga-1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u352-ga-1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u352-ga-1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u352-ga-1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u352-ga-1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u352-ga-1~18.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.17+8-1ubuntu2~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.17+8-1ubuntu2~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.17+8-1ubuntu2~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.17+8-1ubuntu2~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.17+8-1ubuntu2~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.17+8-1ubuntu2~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.17+8-1ubuntu2~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.5+8-2ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.5+8-2ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.5+8-2ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.5+8-2ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.5+8-2ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.5+8-2ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.5+8-2ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u352-ga-1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u352-ga-1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u352-ga-1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u352-ga-1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u352-ga-1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u352-ga-1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u352-ga-1~20.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.17+8-1ubuntu2~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.17+8-1ubuntu2~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.17+8-1ubuntu2~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.17+8-1ubuntu2~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.17+8-1ubuntu2~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.17+8-1ubuntu2~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.17+8-1ubuntu2~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.5+8-2ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.5+8-2ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.5+8-2ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.5+8-2ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.5+8-2ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.5+8-2ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.5+8-2ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-19-demo', 'pkgver': '19.0.1+10-1ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-19-jdk', 'pkgver': '19.0.1+10-1ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-19-jdk-headless', 'pkgver': '19.0.1+10-1ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-19-jre', 'pkgver': '19.0.1+10-1ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-19-jre-headless', 'pkgver': '19.0.1+10-1ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-19-jre-zero', 'pkgver': '19.0.1+10-1ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-19-source', 'pkgver': '19.0.1+10-1ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u352-ga-1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u352-ga-1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u352-ga-1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u352-ga-1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u352-ga-1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u352-ga-1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u352-ga-1~22.04'},
    {'osver': '22.10', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.17+8-1ubuntu2'},
    {'osver': '22.10', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.17+8-1ubuntu2'},
    {'osver': '22.10', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.17+8-1ubuntu2'},
    {'osver': '22.10', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.17+8-1ubuntu2'},
    {'osver': '22.10', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.17+8-1ubuntu2'},
    {'osver': '22.10', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.17+8-1ubuntu2'},
    {'osver': '22.10', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.17+8-1ubuntu2'},
    {'osver': '22.10', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.5+8-2ubuntu1'},
    {'osver': '22.10', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.5+8-2ubuntu1'},
    {'osver': '22.10', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.5+8-2ubuntu1'},
    {'osver': '22.10', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.5+8-2ubuntu1'},
    {'osver': '22.10', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.5+8-2ubuntu1'},
    {'osver': '22.10', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.5+8-2ubuntu1'},
    {'osver': '22.10', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.5+8-2ubuntu1'},
    {'osver': '22.10', 'pkgname': 'openjdk-19-demo', 'pkgver': '19.0.1+10-1'},
    {'osver': '22.10', 'pkgname': 'openjdk-19-jdk', 'pkgver': '19.0.1+10-1'},
    {'osver': '22.10', 'pkgname': 'openjdk-19-jdk-headless', 'pkgver': '19.0.1+10-1'},
    {'osver': '22.10', 'pkgname': 'openjdk-19-jre', 'pkgver': '19.0.1+10-1'},
    {'osver': '22.10', 'pkgname': 'openjdk-19-jre-headless', 'pkgver': '19.0.1+10-1'},
    {'osver': '22.10', 'pkgname': 'openjdk-19-jre-zero', 'pkgver': '19.0.1+10-1'},
    {'osver': '22.10', 'pkgname': 'openjdk-19-source', 'pkgver': '19.0.1+10-1'},
    {'osver': '22.10', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u352-ga-1~22.10'},
    {'osver': '22.10', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u352-ga-1~22.10'},
    {'osver': '22.10', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u352-ga-1~22.10'},
    {'osver': '22.10', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u352-ga-1~22.10'},
    {'osver': '22.10', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u352-ga-1~22.10'},
    {'osver': '22.10', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u352-ga-1~22.10'},
    {'osver': '22.10', 'pkgname': 'openjdk-8-source', 'pkgver': '8u352-ga-1~22.10'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

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
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openjdk-11-demo / openjdk-11-jdk / openjdk-11-jdk-headless / etc');
}
