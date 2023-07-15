#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6077-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175915);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/17");

  script_cve_id(
    "CVE-2023-21930",
    "CVE-2023-21937",
    "CVE-2023-21938",
    "CVE-2023-21939",
    "CVE-2023-21954",
    "CVE-2023-21967",
    "CVE-2023-21968"
  );
  script_xref(name:"USN", value:"6077-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : OpenJDK vulnerabilities (USN-6077-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-6077-1 advisory.

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: JSSE). Supported versions that are affected are Oracle Java SE: 8u361, 8u361-perf, 11.0.18,
    17.0.6, 20; Oracle GraalVM Enterprise Edition: 20.3.9, 21.3.5 and 22.3.1. Difficult to exploit
    vulnerability allows unauthenticated attacker with network access via TLS to compromise Oracle Java SE,
    Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized
    creation, deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM
    Enterprise Edition accessible data as well as unauthorized access to critical data or complete access to
    all Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to
    Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component,
    e.g., through a web service which supplies data to the APIs. (CVE-2023-21930)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Networking). Supported versions that are affected are Oracle Java SE: 8u361, 8u361-perf,
    11.0.18, 17.0.6, 20; Oracle GraalVM Enterprise Edition: 20.3.9, 21.3.5 and 22.3.1. Difficult to exploit
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition
    accessible data. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also
    be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to
    the APIs. (CVE-2023-21937)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Libraries). Supported versions that are affected are Oracle Java SE: 8u361, 8u361-perf,
    11.0.18, 17.0.6, 20; Oracle GraalVM Enterprise Edition: 20.3.8, 21.3.4 and 22.3.0. Difficult to exploit
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition
    accessible data. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not
    apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed
    by an administrator). (CVE-2023-21938)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Swing). Supported versions that are affected are Oracle Java SE: 8u361, 8u361-perf, 11.0.18,
    17.0.6, 20; Oracle GraalVM Enterprise Edition: 20.3.9, 21.3.5 and 22.3.1. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise Oracle Java SE, Oracle GraalVM
    Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized update, insert or
    delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs.
    (CVE-2023-21939)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Hotspot). Supported versions that are affected are Oracle Java SE: 8u361, 8u361-perf, 11.0.18,
    17.0.6; Oracle GraalVM Enterprise Edition: 20.3.9, 21.3.5 and 22.3.1. Difficult to exploit vulnerability
    allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE,
    Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized
    access to critical data or complete access to all Oracle Java SE, Oracle GraalVM Enterprise Edition
    accessible data. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also
    be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to
    the APIs. (CVE-2023-21954)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: JSSE). Supported versions that are affected are Oracle Java SE: 8u361, 8u361-perf, 11.0.18,
    17.0.6, 20; Oracle GraalVM Enterprise Edition: 20.3.9, 21.3.5 and 22.3.1. Difficult to exploit
    vulnerability allows unauthenticated attacker with network access via HTTPS to compromise Oracle Java SE,
    Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle Java SE, Oracle GraalVM
    Enterprise Edition. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also
    be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to
    the APIs. (CVE-2023-21967)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Libraries). Supported versions that are affected are Oracle Java SE: 8u361, 8u361-perf,
    11.0.18, 17.0.6, 20; Oracle GraalVM Enterprise Edition: 20.3.9, 21.3.5 and 22.3.1. Difficult to exploit
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition
    accessible data. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also
    be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to
    the APIs. (CVE-2023-21968)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6077-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21930");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/17");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-20-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-20-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-20-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-20-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-20-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-20-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-20-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-source");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! preg(pattern:"^(16\.04|18\.04|20\.04|22\.04|22\.10|23\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 22.10 / 23.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u372-ga~us1-0ubuntu1~16.04'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u372-ga~us1-0ubuntu1~16.04'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u372-ga~us1-0ubuntu1~16.04'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u372-ga~us1-0ubuntu1~16.04'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u372-ga~us1-0ubuntu1~16.04'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-jamvm', 'pkgver': '8u372-ga~us1-0ubuntu1~16.04'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u372-ga~us1-0ubuntu1~16.04'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u372-ga~us1-0ubuntu1~16.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.19+7~us1-0ubuntu1~18.04.1'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.19+7~us1-0ubuntu1~18.04.1'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.19+7~us1-0ubuntu1~18.04.1'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.19+7~us1-0ubuntu1~18.04.1'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.19+7~us1-0ubuntu1~18.04.1'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.19+7~us1-0ubuntu1~18.04.1'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.19+7~us1-0ubuntu1~18.04.1'},
    {'osver': '18.04', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.7+7~us1-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.7+7~us1-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.7+7~us1-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.7+7~us1-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.7+7~us1-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.7+7~us1-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.7+7~us1-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u372-ga~us1-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u372-ga~us1-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u372-ga~us1-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u372-ga~us1-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u372-ga~us1-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u372-ga~us1-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u372-ga~us1-0ubuntu1~18.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.19+7~us1-0ubuntu1~20.04.1'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.19+7~us1-0ubuntu1~20.04.1'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.19+7~us1-0ubuntu1~20.04.1'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.19+7~us1-0ubuntu1~20.04.1'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.19+7~us1-0ubuntu1~20.04.1'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.19+7~us1-0ubuntu1~20.04.1'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.19+7~us1-0ubuntu1~20.04.1'},
    {'osver': '20.04', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.7+7~us1-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.7+7~us1-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.7+7~us1-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.7+7~us1-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.7+7~us1-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.7+7~us1-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.7+7~us1-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u372-ga~us1-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u372-ga~us1-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u372-ga~us1-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u372-ga~us1-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u372-ga~us1-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u372-ga~us1-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u372-ga~us1-0ubuntu1~20.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.19+7~us1-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.19+7~us1-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.19+7~us1-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.19+7~us1-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.19+7~us1-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.19+7~us1-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.19+7~us1-0ubuntu1~22.04.1'},
    {'osver': '22.04', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.7+7~us1-0ubuntu1~22.04.2'},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.7+7~us1-0ubuntu1~22.04.2'},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.7+7~us1-0ubuntu1~22.04.2'},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.7+7~us1-0ubuntu1~22.04.2'},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.7+7~us1-0ubuntu1~22.04.2'},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.7+7~us1-0ubuntu1~22.04.2'},
    {'osver': '22.04', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.7+7~us1-0ubuntu1~22.04.2'},
    {'osver': '22.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u372-ga~us1-0ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u372-ga~us1-0ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u372-ga~us1-0ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u372-ga~us1-0ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u372-ga~us1-0ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u372-ga~us1-0ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u372-ga~us1-0ubuntu1~22.04'},
    {'osver': '22.10', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.19+7~us1-0ubuntu1~22.10.1'},
    {'osver': '22.10', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.19+7~us1-0ubuntu1~22.10.1'},
    {'osver': '22.10', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.19+7~us1-0ubuntu1~22.10.1'},
    {'osver': '22.10', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.19+7~us1-0ubuntu1~22.10.1'},
    {'osver': '22.10', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.19+7~us1-0ubuntu1~22.10.1'},
    {'osver': '22.10', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.19+7~us1-0ubuntu1~22.10.1'},
    {'osver': '22.10', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.19+7~us1-0ubuntu1~22.10.1'},
    {'osver': '22.10', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.7+7~us1-0ubuntu1~22.10.2'},
    {'osver': '22.10', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.7+7~us1-0ubuntu1~22.10.2'},
    {'osver': '22.10', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.7+7~us1-0ubuntu1~22.10.2'},
    {'osver': '22.10', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.7+7~us1-0ubuntu1~22.10.2'},
    {'osver': '22.10', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.7+7~us1-0ubuntu1~22.10.2'},
    {'osver': '22.10', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.7+7~us1-0ubuntu1~22.10.2'},
    {'osver': '22.10', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.7+7~us1-0ubuntu1~22.10.2'},
    {'osver': '22.10', 'pkgname': 'openjdk-20-demo', 'pkgver': '20.0.1+9~us1-0ubuntu1~22.10'},
    {'osver': '22.10', 'pkgname': 'openjdk-20-jdk', 'pkgver': '20.0.1+9~us1-0ubuntu1~22.10'},
    {'osver': '22.10', 'pkgname': 'openjdk-20-jdk-headless', 'pkgver': '20.0.1+9~us1-0ubuntu1~22.10'},
    {'osver': '22.10', 'pkgname': 'openjdk-20-jre', 'pkgver': '20.0.1+9~us1-0ubuntu1~22.10'},
    {'osver': '22.10', 'pkgname': 'openjdk-20-jre-headless', 'pkgver': '20.0.1+9~us1-0ubuntu1~22.10'},
    {'osver': '22.10', 'pkgname': 'openjdk-20-jre-zero', 'pkgver': '20.0.1+9~us1-0ubuntu1~22.10'},
    {'osver': '22.10', 'pkgname': 'openjdk-20-source', 'pkgver': '20.0.1+9~us1-0ubuntu1~22.10'},
    {'osver': '22.10', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u372-ga~us1-0ubuntu1~22.10'},
    {'osver': '22.10', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u372-ga~us1-0ubuntu1~22.10'},
    {'osver': '22.10', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u372-ga~us1-0ubuntu1~22.10'},
    {'osver': '22.10', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u372-ga~us1-0ubuntu1~22.10'},
    {'osver': '22.10', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u372-ga~us1-0ubuntu1~22.10'},
    {'osver': '22.10', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u372-ga~us1-0ubuntu1~22.10'},
    {'osver': '22.10', 'pkgname': 'openjdk-8-source', 'pkgver': '8u372-ga~us1-0ubuntu1~22.10'},
    {'osver': '23.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.19+7~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.19+7~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.19+7~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.19+7~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.19+7~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.19+7~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.19+7~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.7+7~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.7+7~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.7+7~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.7+7~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.7+7~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.7+7~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.7+7~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-20-demo', 'pkgver': '20.0.1+9~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-20-jdk', 'pkgver': '20.0.1+9~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-20-jdk-headless', 'pkgver': '20.0.1+9~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-20-jre', 'pkgver': '20.0.1+9~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-20-jre-headless', 'pkgver': '20.0.1+9~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-20-jre-zero', 'pkgver': '20.0.1+9~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-20-source', 'pkgver': '20.0.1+9~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u372-ga~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u372-ga~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u372-ga~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u372-ga~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u372-ga~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u372-ga~us1-0ubuntu1~23.04'},
    {'osver': '23.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u372-ga~us1-0ubuntu1~23.04'}
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
    severity   : SECURITY_HOLE,
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
