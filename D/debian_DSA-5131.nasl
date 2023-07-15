#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5131. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(160628);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/09");

  script_cve_id(
    "CVE-2022-21426",
    "CVE-2022-21434",
    "CVE-2022-21443",
    "CVE-2022-21449",
    "CVE-2022-21476",
    "CVE-2022-21496"
  );
  script_xref(name:"IAVA", value:"2022-A-0170-S");

  script_name(english:"Debian DSA-5131-1 : openjdk-11 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5131 advisory.

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/openjdk-11");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5131");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21426");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21434");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21443");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21449");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21476");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21496");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/openjdk-11");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/openjdk-11");
  script_set_attribute(attribute:"solution", value:
"Upgrade the openjdk-11 packages.

For the stable distribution (bullseye), this problem has been fixed in version 11.0.15+10-1~deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21496");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-21476");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-11-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-11-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-11-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-11-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-11-jdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-11-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-11-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-11-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-11-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+|^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0 / 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'openjdk-11-dbg', 'reference': '11.0.15+10-1~deb10u1'},
    {'release': '10.0', 'prefix': 'openjdk-11-demo', 'reference': '11.0.15+10-1~deb10u1'},
    {'release': '10.0', 'prefix': 'openjdk-11-doc', 'reference': '11.0.15+10-1~deb10u1'},
    {'release': '10.0', 'prefix': 'openjdk-11-jdk', 'reference': '11.0.15+10-1~deb10u1'},
    {'release': '10.0', 'prefix': 'openjdk-11-jdk-headless', 'reference': '11.0.15+10-1~deb10u1'},
    {'release': '10.0', 'prefix': 'openjdk-11-jre', 'reference': '11.0.15+10-1~deb10u1'},
    {'release': '10.0', 'prefix': 'openjdk-11-jre-headless', 'reference': '11.0.15+10-1~deb10u1'},
    {'release': '10.0', 'prefix': 'openjdk-11-jre-zero', 'reference': '11.0.15+10-1~deb10u1'},
    {'release': '10.0', 'prefix': 'openjdk-11-source', 'reference': '11.0.15+10-1~deb10u1'},
    {'release': '11.0', 'prefix': 'openjdk-11-dbg', 'reference': '11.0.15+10-1~deb11u1'},
    {'release': '11.0', 'prefix': 'openjdk-11-demo', 'reference': '11.0.15+10-1~deb11u1'},
    {'release': '11.0', 'prefix': 'openjdk-11-doc', 'reference': '11.0.15+10-1~deb11u1'},
    {'release': '11.0', 'prefix': 'openjdk-11-jdk', 'reference': '11.0.15+10-1~deb11u1'},
    {'release': '11.0', 'prefix': 'openjdk-11-jdk-headless', 'reference': '11.0.15+10-1~deb11u1'},
    {'release': '11.0', 'prefix': 'openjdk-11-jre', 'reference': '11.0.15+10-1~deb11u1'},
    {'release': '11.0', 'prefix': 'openjdk-11-jre-headless', 'reference': '11.0.15+10-1~deb11u1'},
    {'release': '11.0', 'prefix': 'openjdk-11-jre-zero', 'reference': '11.0.15+10-1~deb11u1'},
    {'release': '11.0', 'prefix': 'openjdk-11-source', 'reference': '11.0.15+10-1~deb11u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openjdk-11-dbg / openjdk-11-demo / openjdk-11-doc / openjdk-11-jdk / etc');
}
