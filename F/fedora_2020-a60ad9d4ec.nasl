#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-a60ad9d4ec.
#

include("compat.inc");

if (description)
{
  script_id(136682);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/16");

  script_cve_id("CVE-2020-2754", "CVE-2020-2755", "CVE-2020-2756", "CVE-2020-2757", "CVE-2020-2773", "CVE-2020-2781", "CVE-2020-2800", "CVE-2020-2803", "CVE-2020-2805", "CVE-2020-2830");
  script_xref(name:"FEDORA", value:"2020-a60ad9d4ec");

  script_name(english:"Fedora 31 : 1:java-1.8.0-openjdk (2020-a60ad9d4ec)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Update to OpenJDK 8u252 (April Critical Patch Update)

  - JDK-8223898, CVE-2020-2754: Forward references to
    Nashorn

  - JDK-8223904, CVE-2020-2755: Improve Nashorn matching

  - JDK-8224541, CVE-2020-2756: Better mapping of serial
    ENUMs

  - JDK-8224549, CVE-2020-2757: Less Blocking Array Queues

  - JDK-8225603: Enhancement for big integers

  - JDK-8227542: Manifest improved jar headers

  - JDK-8231415, CVE-2020-2773: Better signatures in XML

  - JDK-8233250: Better X11 rendering

  - JDK-8233410: Better Build Scripting

  - JDK-8234027: Better JCEKS key support

  - JDK-8234408, CVE-2020-2781: Improve TLS session handling

  - JDK-8234825, CVE-2020-2800: Better Headings for HTTP
    Servers

  - JDK-8234841, CVE-2020-2803: Enhance buffering of byte
    buffers

  - JDK-8235274, CVE-2020-2805: Enhance typing of methods

  - JDK-8236201, CVE-2020-2830: Better Scanner conversions

  - JDK-8238960: linux-i586 builds are inconsistent as the
    newly build jdk is not able to reserve enough space for
    object heap

Full release notes: https://bitly.com/oj8u252

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bitly.com/oj8u252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-a60ad9d4ec"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected 1:java-1.8.0-openjdk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2800");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:31");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/18");
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
if (! preg(pattern:"^31([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 31", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC31", reference:"java-1.8.0-openjdk-1.8.0.252.b09-0.fc31", epoch:"1")) flag++;


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
