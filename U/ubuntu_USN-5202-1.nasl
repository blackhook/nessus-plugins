##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5202-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(156155);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2021-2341",
    "CVE-2021-2369",
    "CVE-2021-2388",
    "CVE-2021-35550",
    "CVE-2021-35556",
    "CVE-2021-35559",
    "CVE-2021-35561",
    "CVE-2021-35564",
    "CVE-2021-35565",
    "CVE-2021-35567",
    "CVE-2021-35578",
    "CVE-2021-35586",
    "CVE-2021-35588",
    "CVE-2021-35603"
  );
  script_xref(name:"USN", value:"5202-1");
  script_xref(name:"IAVA", value:"2021-A-0481-S");
  script_xref(name:"IAVA", value:"2021-A-0327-S");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 21.04 / 21.10 : OpenJDK vulnerabilities (USN-5202-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5202-1 advisory.

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Networking). Supported versions that are affected are Java SE: 7u301, 8u291, 11.0.11, 16.0.1; Oracle
    GraalVM Enterprise Edition: 20.3.2 and 21.1.0. Difficult to exploit vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise
    Edition. Successful attacks require human interaction from a person other than the attacker. Successful
    attacks of this vulnerability can result in unauthorized read access to a subset of Java SE, Oracle
    GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability does not apply to Java deployments, typically in servers, that load and run
    only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 3.1 (Confidentiality
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N). (CVE-2021-2341)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Library). Supported versions that are affected are Java SE: 7u301, 8u291, 11.0.11, 16.0.1; Oracle GraalVM
    Enterprise Edition: 20.3.2 and 21.1.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks require human interaction from a person other than the attacker. Successful attacks of
    this vulnerability can result in unauthorized update, insert or delete access to some of Java SE, Oracle
    GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability does not apply to Java deployments, typically in servers, that load and run
    only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 4.3 (Integrity impacts).
    CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N). (CVE-2021-2369)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Hotspot). Supported versions that are affected are Java SE: 8u291, 11.0.11, 16.0.1; Oracle GraalVM
    Enterprise Edition: 20.3.2 and 21.1.0. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks require human interaction from a person other than the attacker. Successful attacks of
    this vulnerability can result in takeover of Java SE, Oracle GraalVM Enterprise Edition. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). CVSS 3.1 Base Score 7.5 (Confidentiality, Integrity and Availability impacts). CVSS
    Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H). (CVE-2021-2388)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    JSSE). Supported versions that are affected are Java SE: 7u311, 8u301, 11.0.12; Oracle GraalVM Enterprise
    Edition: 20.3.3 and 21.2.0. Difficult to exploit vulnerability allows unauthenticated attacker with
    network access via TLS to compromise Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of
    this vulnerability can result in unauthorized access to critical data or complete access to all Java SE,
    Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability can also be exploited by using APIs in the specified Component, e.g., through
    a web service which supplies data to the APIs. CVSS 3.1 Base Score 5.9 (Confidentiality impacts). CVSS
    Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N). (CVE-2021-35550)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Swing). Supported versions that are affected are Java SE: 7u311, 8u301, 11.0.12, 17; Oracle GraalVM
    Enterprise Edition: 20.3.3 and 21.2.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to
    Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that
    load and run only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 5.3
    (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L). (CVE-2021-35556)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Swing). Supported versions that are affected are Java SE: 7u311, 8u301, 11.0.12, 17; Oracle GraalVM
    Enterprise Edition: 20.3.3 and 21.2.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to
    Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component,
    e.g., through a web service which supplies data to the APIs. CVSS 3.1 Base Score 5.3 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L). (CVE-2021-35559)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Utility). Supported versions that are affected are Java SE: 7u311, 8u301, 11.0.12, 17; Oracle GraalVM
    Enterprise Edition: 20.3.3 and 21.2.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to
    Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component,
    e.g., through a web service which supplies data to the APIs. CVSS 3.1 Base Score 5.3 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L). (CVE-2021-35561)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Keytool). Supported versions that are affected are Java SE: 7u311, 8u301, 11.0.12, 17; Oracle GraalVM
    Enterprise Edition: 20.3.3 and 21.2.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to
    some of Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to
    Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component,
    e.g., through a web service which supplies data to the APIs. CVSS 3.1 Base Score 5.3 (Integrity impacts).
    CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N). (CVE-2021-35564)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    JSSE). Supported versions that are affected are Java SE: 7u311, 8u301, 11.0.12; Oracle GraalVM Enterprise
    Edition: 20.3.3 and 21.2.0. Easily exploitable vulnerability allows unauthenticated attacker with network
    access via TLS to compromise Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of
    Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability can only be exploited by supplying
    data to APIs in the specified Component without using Untrusted Java Web Start applications or Untrusted
    Java applets, such as through a web service. CVSS 3.1 Base Score 5.3 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L). (CVE-2021-35565)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Libraries). Supported versions that are affected are Java SE: 8u301, 11.0.12, 17; Oracle GraalVM
    Enterprise Edition: 20.3.3 and 21.2.0. Easily exploitable vulnerability allows low privileged attacker
    with network access via Kerberos to compromise Java SE, Oracle GraalVM Enterprise Edition. Successful
    attacks require human interaction from a person other than the attacker and while the vulnerability is in
    Java SE, Oracle GraalVM Enterprise Edition, attacks may significantly impact additional products.
    Successful attacks of this vulnerability can result in unauthorized access to critical data or complete
    access to all Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies
    to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component,
    e.g., through a web service which supplies data to the APIs. CVSS 3.1 Base Score 6.8 (Confidentiality
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:N/A:N). (CVE-2021-35567)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    JSSE). Supported versions that are affected are Java SE: 8u301, 11.0.12, 17; Oracle GraalVM Enterprise
    Edition: 20.3.3 and 21.2.0. Easily exploitable vulnerability allows unauthenticated attacker with network
    access via TLS to compromise Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of
    Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability can only be exploited by supplying
    data to APIs in the specified Component without using Untrusted Java Web Start applications or Untrusted
    Java applets, such as through a web service. CVSS 3.1 Base Score 5.3 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L). (CVE-2021-35578)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    ImageIO). Supported versions that are affected are Java SE: 7u311, 8u301, 11.0.12, 17; Oracle GraalVM
    Enterprise Edition: 20.3.3 and 21.2.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to
    Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component,
    e.g., through a web service which supplies data to the APIs. CVSS 3.1 Base Score 5.3 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L). (CVE-2021-35586)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Hotspot). Supported versions that are affected are Java SE: 7u311, 8u301; Oracle GraalVM Enterprise
    Edition: 20.3.3 and 21.2.0. Difficult to exploit vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition. Successful
    attacks require human interaction from a person other than the attacker. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of
    Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability can also be exploited by using APIs in the specified Component, e.g., through
    a web service which supplies data to the APIs. CVSS 3.1 Base Score 3.1 (Availability impacts). CVSS
    Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L). (CVE-2021-35588)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    JSSE). Supported versions that are affected are Java SE: 7u311, 8u301, 11.0.12, 17; Oracle GraalVM
    Enterprise Edition: 20.3.3 and 21.2.0. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via TLS to compromise Java SE, Oracle GraalVM Enterprise Edition. Successful attacks
    of this vulnerability can result in unauthorized read access to a subset of Java SE, Oracle GraalVM
    Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run
    untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This
    vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service
    which supplies data to the APIs. CVSS 3.1 Base Score 3.7 (Confidentiality impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N). (CVE-2021-35603)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5202-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35550");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-2388");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-11-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-source");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! preg(pattern:"^(16\.04|18\.04|20\.04|21\.04|21\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 21.04 / 21.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u312-b07-0ubuntu1~16.04'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u312-b07-0ubuntu1~16.04'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u312-b07-0ubuntu1~16.04'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u312-b07-0ubuntu1~16.04'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u312-b07-0ubuntu1~16.04'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-jamvm', 'pkgver': '8u312-b07-0ubuntu1~16.04'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u312-b07-0ubuntu1~16.04'},
    {'osver': '16.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u312-b07-0ubuntu1~16.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.13+8-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.13+8-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.13+8-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.13+8-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.13+8-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.13+8-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.13+8-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u312-b07-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u312-b07-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u312-b07-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u312-b07-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u312-b07-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u312-b07-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u312-b07-0ubuntu1~18.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.13+8-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.13+8-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.13+8-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.13+8-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.13+8-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.13+8-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.13+8-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u312-b07-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u312-b07-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u312-b07-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u312-b07-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u312-b07-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u312-b07-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u312-b07-0ubuntu1~20.04'},
    {'osver': '21.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.13+8-0ubuntu1~21.04'},
    {'osver': '21.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.13+8-0ubuntu1~21.04'},
    {'osver': '21.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.13+8-0ubuntu1~21.04'},
    {'osver': '21.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.13+8-0ubuntu1~21.04'},
    {'osver': '21.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.13+8-0ubuntu1~21.04'},
    {'osver': '21.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.13+8-0ubuntu1~21.04'},
    {'osver': '21.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.13+8-0ubuntu1~21.04'},
    {'osver': '21.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u312-b07-0ubuntu1~21.04'},
    {'osver': '21.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u312-b07-0ubuntu1~21.04'},
    {'osver': '21.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u312-b07-0ubuntu1~21.04'},
    {'osver': '21.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u312-b07-0ubuntu1~21.04'},
    {'osver': '21.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u312-b07-0ubuntu1~21.04'},
    {'osver': '21.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u312-b07-0ubuntu1~21.04'},
    {'osver': '21.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u312-b07-0ubuntu1~21.04'},
    {'osver': '21.10', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.13+8-0ubuntu1~21.10'},
    {'osver': '21.10', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.13+8-0ubuntu1~21.10'},
    {'osver': '21.10', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.13+8-0ubuntu1~21.10'},
    {'osver': '21.10', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.13+8-0ubuntu1~21.10'},
    {'osver': '21.10', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.13+8-0ubuntu1~21.10'},
    {'osver': '21.10', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.13+8-0ubuntu1~21.10'},
    {'osver': '21.10', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.13+8-0ubuntu1~21.10'},
    {'osver': '21.10', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u312-b07-0ubuntu1~21.10'},
    {'osver': '21.10', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u312-b07-0ubuntu1~21.10'},
    {'osver': '21.10', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u312-b07-0ubuntu1~21.10'},
    {'osver': '21.10', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u312-b07-0ubuntu1~21.10'},
    {'osver': '21.10', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u312-b07-0ubuntu1~21.10'},
    {'osver': '21.10', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u312-b07-0ubuntu1~21.10'},
    {'osver': '21.10', 'pkgname': 'openjdk-8-source', 'pkgver': '8u312-b07-0ubuntu1~21.10'}
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
