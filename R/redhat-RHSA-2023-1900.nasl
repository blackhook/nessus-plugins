#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:1900. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(174516);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id(
    "CVE-2023-21930",
    "CVE-2023-21937",
    "CVE-2023-21938",
    "CVE-2023-21939",
    "CVE-2023-21954",
    "CVE-2023-21967",
    "CVE-2023-21968"
  );
  script_xref(name:"RHSA", value:"2023:1900");

  script_name(english:"RHEL 9 : java-17-openjdk (RHSA-2023:1900)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:1900 advisory.

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
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21930");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21937");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21938");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21939");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21954");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21967");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21968");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:1900");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21930");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 158, 200, 358, 924);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-17-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-17-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-17-openjdk-demo-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-17-openjdk-demo-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-17-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-17-openjdk-devel-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-17-openjdk-devel-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-17-openjdk-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-17-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-17-openjdk-headless-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-17-openjdk-headless-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-17-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-17-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-17-openjdk-jmods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-17-openjdk-jmods-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-17-openjdk-jmods-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-17-openjdk-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-17-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-17-openjdk-src-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-17-openjdk-src-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-17-openjdk-static-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-17-openjdk-static-libs-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-17-openjdk-static-libs-slowdebug");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '9.0')) audit(AUDIT_OS_NOT, 'Red Hat 9.0', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/e4s/rhel9/9.0/aarch64/appstream/debug',
      'content/e4s/rhel9/9.0/aarch64/appstream/os',
      'content/e4s/rhel9/9.0/aarch64/appstream/source/SRPMS',
      'content/e4s/rhel9/9.0/aarch64/baseos/debug',
      'content/e4s/rhel9/9.0/aarch64/baseos/os',
      'content/e4s/rhel9/9.0/aarch64/baseos/source/SRPMS',
      'content/e4s/rhel9/9.0/aarch64/highavailability/debug',
      'content/e4s/rhel9/9.0/aarch64/highavailability/os',
      'content/e4s/rhel9/9.0/aarch64/highavailability/source/SRPMS',
      'content/e4s/rhel9/9.0/ppc64le/appstream/debug',
      'content/e4s/rhel9/9.0/ppc64le/appstream/os',
      'content/e4s/rhel9/9.0/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel9/9.0/ppc64le/baseos/debug',
      'content/e4s/rhel9/9.0/ppc64le/baseos/os',
      'content/e4s/rhel9/9.0/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel9/9.0/ppc64le/highavailability/debug',
      'content/e4s/rhel9/9.0/ppc64le/highavailability/os',
      'content/e4s/rhel9/9.0/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel9/9.0/ppc64le/resilientstorage/debug',
      'content/e4s/rhel9/9.0/ppc64le/resilientstorage/os',
      'content/e4s/rhel9/9.0/ppc64le/resilientstorage/source/SRPMS',
      'content/e4s/rhel9/9.0/ppc64le/sap-solutions/debug',
      'content/e4s/rhel9/9.0/ppc64le/sap-solutions/os',
      'content/e4s/rhel9/9.0/ppc64le/sap-solutions/source/SRPMS',
      'content/e4s/rhel9/9.0/ppc64le/sap/debug',
      'content/e4s/rhel9/9.0/ppc64le/sap/os',
      'content/e4s/rhel9/9.0/ppc64le/sap/source/SRPMS',
      'content/e4s/rhel9/9.0/x86_64/appstream/debug',
      'content/e4s/rhel9/9.0/x86_64/appstream/os',
      'content/e4s/rhel9/9.0/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel9/9.0/x86_64/baseos/debug',
      'content/e4s/rhel9/9.0/x86_64/baseos/os',
      'content/e4s/rhel9/9.0/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel9/9.0/x86_64/highavailability/debug',
      'content/e4s/rhel9/9.0/x86_64/highavailability/os',
      'content/e4s/rhel9/9.0/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel9/9.0/x86_64/nfv/debug',
      'content/e4s/rhel9/9.0/x86_64/nfv/os',
      'content/e4s/rhel9/9.0/x86_64/nfv/source/SRPMS',
      'content/e4s/rhel9/9.0/x86_64/resilientstorage/debug',
      'content/e4s/rhel9/9.0/x86_64/resilientstorage/os',
      'content/e4s/rhel9/9.0/x86_64/resilientstorage/source/SRPMS',
      'content/e4s/rhel9/9.0/x86_64/rt/debug',
      'content/e4s/rhel9/9.0/x86_64/rt/os',
      'content/e4s/rhel9/9.0/x86_64/rt/source/SRPMS',
      'content/e4s/rhel9/9.0/x86_64/sap-solutions/debug',
      'content/e4s/rhel9/9.0/x86_64/sap-solutions/os',
      'content/e4s/rhel9/9.0/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel9/9.0/x86_64/sap/debug',
      'content/e4s/rhel9/9.0/x86_64/sap/os',
      'content/e4s/rhel9/9.0/x86_64/sap/source/SRPMS',
      'content/eus/rhel9/9.0/aarch64/appstream/debug',
      'content/eus/rhel9/9.0/aarch64/appstream/os',
      'content/eus/rhel9/9.0/aarch64/appstream/source/SRPMS',
      'content/eus/rhel9/9.0/aarch64/baseos/debug',
      'content/eus/rhel9/9.0/aarch64/baseos/os',
      'content/eus/rhel9/9.0/aarch64/baseos/source/SRPMS',
      'content/eus/rhel9/9.0/aarch64/codeready-builder/debug',
      'content/eus/rhel9/9.0/aarch64/codeready-builder/os',
      'content/eus/rhel9/9.0/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.0/aarch64/highavailability/debug',
      'content/eus/rhel9/9.0/aarch64/highavailability/os',
      'content/eus/rhel9/9.0/aarch64/highavailability/source/SRPMS',
      'content/eus/rhel9/9.0/aarch64/supplementary/debug',
      'content/eus/rhel9/9.0/aarch64/supplementary/os',
      'content/eus/rhel9/9.0/aarch64/supplementary/source/SRPMS',
      'content/eus/rhel9/9.0/ppc64le/appstream/debug',
      'content/eus/rhel9/9.0/ppc64le/appstream/os',
      'content/eus/rhel9/9.0/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel9/9.0/ppc64le/baseos/debug',
      'content/eus/rhel9/9.0/ppc64le/baseos/os',
      'content/eus/rhel9/9.0/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel9/9.0/ppc64le/codeready-builder/debug',
      'content/eus/rhel9/9.0/ppc64le/codeready-builder/os',
      'content/eus/rhel9/9.0/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.0/ppc64le/highavailability/debug',
      'content/eus/rhel9/9.0/ppc64le/highavailability/os',
      'content/eus/rhel9/9.0/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel9/9.0/ppc64le/resilientstorage/debug',
      'content/eus/rhel9/9.0/ppc64le/resilientstorage/os',
      'content/eus/rhel9/9.0/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel9/9.0/ppc64le/sap-solutions/debug',
      'content/eus/rhel9/9.0/ppc64le/sap-solutions/os',
      'content/eus/rhel9/9.0/ppc64le/sap-solutions/source/SRPMS',
      'content/eus/rhel9/9.0/ppc64le/sap/debug',
      'content/eus/rhel9/9.0/ppc64le/sap/os',
      'content/eus/rhel9/9.0/ppc64le/sap/source/SRPMS',
      'content/eus/rhel9/9.0/ppc64le/supplementary/debug',
      'content/eus/rhel9/9.0/ppc64le/supplementary/os',
      'content/eus/rhel9/9.0/ppc64le/supplementary/source/SRPMS',
      'content/eus/rhel9/9.0/x86_64/appstream/debug',
      'content/eus/rhel9/9.0/x86_64/appstream/os',
      'content/eus/rhel9/9.0/x86_64/appstream/source/SRPMS',
      'content/eus/rhel9/9.0/x86_64/baseos/debug',
      'content/eus/rhel9/9.0/x86_64/baseos/os',
      'content/eus/rhel9/9.0/x86_64/baseos/source/SRPMS',
      'content/eus/rhel9/9.0/x86_64/codeready-builder/debug',
      'content/eus/rhel9/9.0/x86_64/codeready-builder/os',
      'content/eus/rhel9/9.0/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.0/x86_64/highavailability/debug',
      'content/eus/rhel9/9.0/x86_64/highavailability/os',
      'content/eus/rhel9/9.0/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel9/9.0/x86_64/resilientstorage/debug',
      'content/eus/rhel9/9.0/x86_64/resilientstorage/os',
      'content/eus/rhel9/9.0/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel9/9.0/x86_64/sap-solutions/debug',
      'content/eus/rhel9/9.0/x86_64/sap-solutions/os',
      'content/eus/rhel9/9.0/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel9/9.0/x86_64/sap/debug',
      'content/eus/rhel9/9.0/x86_64/sap/os',
      'content/eus/rhel9/9.0/x86_64/sap/source/SRPMS',
      'content/eus/rhel9/9.0/x86_64/supplementary/debug',
      'content/eus/rhel9/9.0/x86_64/supplementary/os',
      'content/eus/rhel9/9.0/x86_64/supplementary/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'java-17-openjdk-17.0.7.0.7-1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-demo-17.0.7.0.7-1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-demo-fastdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-demo-fastdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-demo-fastdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-demo-slowdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-devel-17.0.7.0.7-1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-devel-fastdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-devel-fastdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-devel-fastdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-devel-slowdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-fastdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-fastdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-fastdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-headless-17.0.7.0.7-1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-headless-fastdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-headless-fastdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-headless-fastdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-headless-slowdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-javadoc-17.0.7.0.7-1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-javadoc-zip-17.0.7.0.7-1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-jmods-17.0.7.0.7-1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-jmods-fastdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-jmods-fastdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-jmods-fastdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-jmods-slowdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-slowdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-src-17.0.7.0.7-1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-src-fastdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-src-fastdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-src-fastdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-src-slowdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-static-libs-17.0.7.0.7-1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-static-libs-fastdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-static-libs-fastdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-static-libs-fastdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-17-openjdk-static-libs-slowdebug-17.0.7.0.7-1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Extended Update Support or Update Services for SAP Solutions repositories.\n' +
    'Access to these repositories requires a paid RHEL subscription.\n';
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = subscription_caveat + rpm_report_get() + redhat_report_repo_caveat();
  else extra = subscription_caveat + rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-17-openjdk / java-17-openjdk-demo / etc');
}
