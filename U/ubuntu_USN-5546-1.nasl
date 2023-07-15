##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5546-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163855);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-21426",
    "CVE-2022-21434",
    "CVE-2022-21443",
    "CVE-2022-21449",
    "CVE-2022-21476",
    "CVE-2022-21496",
    "CVE-2022-21540",
    "CVE-2022-21541",
    "CVE-2022-21549",
    "CVE-2022-34169"
  );
  script_xref(name:"USN", value:"5546-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS : OpenJDK vulnerabilities (USN-5546-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5546-1 advisory.

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: JAXP). Supported versions that are affected are Oracle Java SE: 7u331, 8u321, 11.0.14, 17.0.2,
    18; Oracle GraalVM Enterprise Edition: 20.3.5, 21.3.1 and 22.0.0.2. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE,
    Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM Enterprise
    Edition. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java
    Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes
    from the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by
    using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS
    3.1 Base Score 5.3 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2022-21426)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Libraries). Supported versions that are affected are Oracle Java SE: 7u331, 8u321, 11.0.14,
    17.0.2, 18; Oracle GraalVM Enterprise Edition: 20.3.5, 21.3.1 and 22.0.0.2. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition
    accessible data. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also
    be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to
    the APIs. CVSS 3.1 Base Score 5.3 (Integrity impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N). (CVE-2022-21434)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Libraries). Supported versions that are affected are Oracle Java SE: 7u331, 8u321, 11.0.14,
    17.0.2, 18; Oracle GraalVM Enterprise Edition: 20.3.5, 21.3.1 and 22.0.0.2. Difficult to exploit
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM
    Enterprise Edition. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also
    be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to
    the APIs. CVSS 3.1 Base Score 3.7 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L). (CVE-2022-21443)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Libraries). Supported versions that are affected are Oracle Java SE: 17.0.2 and 18; Oracle
    GraalVM Enterprise Edition: 21.3.1 and 22.0.0.2. Easily exploitable vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM
    Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized creation, deletion
    or modification access to critical data or all Oracle Java SE, Oracle GraalVM Enterprise Edition
    accessible data. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also
    be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to
    the APIs. CVSS 3.1 Base Score 7.5 (Integrity impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N). (CVE-2022-21449)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Libraries). Supported versions that are affected are Oracle Java SE: 7u331, 8u321, 11.0.14,
    17.0.2, 18; Oracle GraalVM Enterprise Edition: 20.3.5, 21.3.1 and 22.0.0.2. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in
    unauthorized access to critical data or complete access to all Oracle Java SE, Oracle GraalVM Enterprise
    Edition accessible data. Note: This vulnerability applies to Java deployments, typically in clients
    running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code
    (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability
    can also be exploited by using APIs in the specified Component, e.g., through a web service which supplies
    data to the APIs. CVSS 3.1 Base Score 7.5 (Confidentiality impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N). (CVE-2022-21476)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: JNDI). Supported versions that are affected are Oracle Java SE: 7u331, 8u321, 11.0.14, 17.0.2,
    18; Oracle GraalVM Enterprise Edition: 20.3.5, 21.3.1 and 22.0.0.2. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE,
    Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition accessible
    data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java
    Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes
    from the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by
    using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS
    3.1 Base Score 5.3 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N).
    (CVE-2022-21496)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Hotspot). Supported versions that are affected are Oracle Java SE: 7u343, 8u333, 11.0.15.1,
    17.0.3.1, 18.0.1.1; Oracle GraalVM Enterprise Edition: 20.3.6, 21.3.2 and 22.1.0. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in
    unauthorized read access to a subset of Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from
    the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.1
    Base Score 5.3 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N).
    (CVE-2022-21540)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Hotspot). Supported versions that are affected are Oracle Java SE: 7u343, 8u333, 11.0.15.1,
    17.0.3.1, 18.0.1.1; Oracle GraalVM Enterprise Edition: 20.3.6, 21.3.2 and 22.1.0. Difficult to exploit
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in
    unauthorized creation, deletion or modification access to critical data or all Oracle Java SE, Oracle
    GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability can also be exploited by using APIs in the specified Component, e.g., through
    a web service which supplies data to the APIs. CVSS 3.1 Base Score 5.9 (Integrity impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N). (CVE-2022-21541)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Libraries). Supported versions that are affected are Oracle Java SE: 17.0.3.1; Oracle GraalVM
    Enterprise Edition: 21.3.2 and 22.1.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise
    Edition. Successful attacks of this vulnerability can result in unauthorized update, insert or delete
    access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.1
    Base Score 5.3 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N).
    (CVE-2022-21549)

  - The Apache Xalan Java XSLT library is vulnerable to an integer truncation issue when processing malicious
    XSLT stylesheets. This can be used to corrupt Java class files generated by the internal XSLTC compiler
    and execute arbitrary Java bytecode. The Apache Xalan Java project is dormant and in the process of being
    retired. No future releases of Apache Xalan Java to address this issue are expected. Note: Java runtimes
    (such as OpenJDK) include repackaged copies of Xalan. (CVE-2022-34169)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5546-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21496");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-34169");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-18-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-18-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-18-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-18-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-18-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-18-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-18-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openjdk-8-jre-headless");
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
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04|22\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.16+8-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.16+8-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.16+8-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.16+8-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.16+8-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.16+8-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.16+8-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.4+8-1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.4+8-1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.4+8-1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.4+8-1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.4+8-1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.4+8-1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.4+8-1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u342-b07-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u342-b07-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u342-b07-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u342-b07-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u342-b07-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u342-b07-0ubuntu1~18.04'},
    {'osver': '18.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u342-b07-0ubuntu1~18.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.16+8-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.16+8-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.16+8-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.16+8-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.16+8-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.16+8-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.16+8-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.4+8-1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.4+8-1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.4+8-1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.4+8-1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.4+8-1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.4+8-1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.4+8-1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u342-b07-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u342-b07-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u342-b07-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u342-b07-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u342-b07-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u342-b07-0ubuntu1~20.04'},
    {'osver': '20.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u342-b07-0ubuntu1~20.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-11-demo', 'pkgver': '11.0.16+8-0ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jdk', 'pkgver': '11.0.16+8-0ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jdk-headless', 'pkgver': '11.0.16+8-0ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jre', 'pkgver': '11.0.16+8-0ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jre-headless', 'pkgver': '11.0.16+8-0ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-11-jre-zero', 'pkgver': '11.0.16+8-0ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-11-source', 'pkgver': '11.0.16+8-0ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-17-demo', 'pkgver': '17.0.4+8-1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jdk', 'pkgver': '17.0.4+8-1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jdk-headless', 'pkgver': '17.0.4+8-1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jre', 'pkgver': '17.0.4+8-1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jre-headless', 'pkgver': '17.0.4+8-1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-17-jre-zero', 'pkgver': '17.0.4+8-1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-17-source', 'pkgver': '17.0.4+8-1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-18-demo', 'pkgver': '18.0.2+9-2~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-18-jdk', 'pkgver': '18.0.2+9-2~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-18-jdk-headless', 'pkgver': '18.0.2+9-2~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-18-jre', 'pkgver': '18.0.2+9-2~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-18-jre-headless', 'pkgver': '18.0.2+9-2~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-18-jre-zero', 'pkgver': '18.0.2+9-2~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-18-source', 'pkgver': '18.0.2+9-2~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-8-demo', 'pkgver': '8u342-b07-0ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jdk', 'pkgver': '8u342-b07-0ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jdk-headless', 'pkgver': '8u342-b07-0ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jre', 'pkgver': '8u342-b07-0ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jre-headless', 'pkgver': '8u342-b07-0ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-8-jre-zero', 'pkgver': '8u342-b07-0ubuntu1~22.04'},
    {'osver': '22.04', 'pkgname': 'openjdk-8-source', 'pkgver': '8u342-b07-0ubuntu1~22.04'}
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
