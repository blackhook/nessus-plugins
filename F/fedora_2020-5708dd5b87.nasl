#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-5708dd5b87.
#

include("compat.inc");

if (description)
{
  script_id(141902);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-14779", "CVE-2020-14781", "CVE-2020-14782", "CVE-2020-14792", "CVE-2020-14796", "CVE-2020-14797", "CVE-2020-14798", "CVE-2020-14803");
  script_xref(name:"FEDORA", value:"2020-5708dd5b87");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Fedora 33 : 1:java-1.8.0-openjdk (2020-5708dd5b87)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"New in release OpenJDK 8u272 (2020-10-20):
===========================================

Full versions of these release notes can be found at :

- https://bitly.com/openjdk8u272

- https://builds.shipilev.net/backports-monitor/release-notes-openjdk8u272.txt

## New features

  - JDK-8245468: Add TLSv1.3 implementation classes from
    11.0.7

## Security fixes

  - JDK-8233624: Enhance JNI linkage

  - JDK-8236196: Improve string pooling

  - JDK-8236862, CVE-2020-14779: Enhance support of Proxy
    class

  - JDK-8237990, CVE-2020-14781: Enhanced LDAP contexts

  - JDK-8237995, CVE-2020-14782: Enhance certificate
    processing

  - JDK-8240124: Better VM Interning

  - JDK-8241114, CVE-2020-14792: Better range handling

  - JDK-8242680, CVE-2020-14796: Improved URI Support

  - JDK-8242685, CVE-2020-14797: Better Path Validation

  - JDK-8242695, CVE-2020-14798: Enhanced buffer support

  - JDK-8243302: Advanced class supports

  - JDK-8244136, CVE-2020-14803: Improved Buffer supports

  - JDK-8244479: Further constrain certificates

  - JDK-8244955: Additional Fix for JDK-8240124

  - JDK-8245407: Enhance zoning of times

  - JDK-8245412: Better class definitions

  - JDK-8245417: Improve certificate chain handling

  - JDK-8248574: Improve jpeg processing

  - JDK-8249927: Specify limits of
    jdk.serialProxyInterfaceLimit

  - JDK-8253019: Enhanced JPEG decoding

## JDK-8254177: US/Pacific-New Zone name removed as part of
tzdata2020b

Following JDK's update to tzdata2020b, the long-obsolete files
pacificnew and systemv have been removed. As a result, the
'US/Pacific-New' zone name declared in the pacificnew data file is no
longer available for use.

Information regarding the update can be viewed at
https://mm.icann.org/pipermail/tz-announce/2020-October/000059.html

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-5708dd5b87"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mm.icann.org/pipermail/tz-announce/2020-October/000059.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected 1:java-1.8.0-openjdk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14792");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:33");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^33([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 33", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC33", reference:"java-1.8.0-openjdk-1.8.0.272.b10-0.fc33", epoch:"1")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "1:java-1.8.0-openjdk");
}
