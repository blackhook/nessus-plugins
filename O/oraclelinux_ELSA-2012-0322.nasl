#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0322 and 
# Oracle Linux Security Advisory ELSA-2012-0322 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68487);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/08");

  script_cve_id(
    "CVE-2011-3563",
    "CVE-2011-3571",
    "CVE-2011-5035",
    "CVE-2012-0497",
    "CVE-2012-0501",
    "CVE-2012-0502",
    "CVE-2012-0503",
    "CVE-2012-0505",
    "CVE-2012-0506",
    "CVE-2012-0507"
  );
  script_bugtraq_id(
    51194,
    51467,
    52009,
    52011,
    52012,
    52013,
    52014,
    52017,
    52018,
    52161
  );
  script_xref(name:"RHSA", value:"2012:0322");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Oracle Linux 5 : java-1.6.0-openjdk (ELSA-2012-0322)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"From Red Hat Security Advisory 2012:0322 :

Updated java-1.6.0-openjdk packages that fix several security issues
are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

These packages provide the OpenJDK 6 Java Runtime Environment and the
OpenJDK 6 Software Development Kit.

It was discovered that Java2D did not properly check graphics
rendering objects before passing them to the native renderer.
Malicious input, or an untrusted Java application or applet could use
this flaw to crash the Java Virtual Machine (JVM), or bypass Java
sandbox restrictions. (CVE-2012-0497)

It was discovered that the exception thrown on deserialization failure
did not always contain a proper identification of the cause of the
failure. An untrusted Java application or applet could use this flaw
to bypass Java sandbox restrictions. (CVE-2012-0505)

The AtomicReferenceArray class implementation did not properly check
if the array was of the expected Object[] type. A malicious Java
application or applet could use this flaw to bypass Java sandbox
restrictions. (CVE-2011-3571)

It was discovered that the use of TimeZone.setDefault() was not
restricted by the SecurityManager, allowing an untrusted Java
application or applet to set a new default time zone, and hence bypass
Java sandbox restrictions. (CVE-2012-0503)

The HttpServer class did not limit the number of headers read from
HTTP requests. A remote attacker could use this flaw to make an
application using HttpServer use an excessive amount of CPU time via a
specially crafted request. This update introduces a header count limit
controlled using the sun.net.httpserver.maxReqHeaders property. The
default value is 200. (CVE-2011-5035)

The Java Sound component did not properly check buffer boundaries.
Malicious input, or an untrusted Java application or applet could use
this flaw to cause the Java Virtual Machine (JVM) to crash or disclose
a portion of its memory. (CVE-2011-3563)

A flaw was found in the AWT KeyboardFocusManager that could allow an
untrusted Java application or applet to acquire keyboard focus and
possibly steal sensitive information. (CVE-2012-0502)

It was discovered that the CORBA (Common Object Request Broker
Architecture) implementation in Java did not properly protect
repository identifiers on certain CORBA objects. This could have been
used to modify immutable object data. (CVE-2012-0506)

An off-by-one flaw, causing a stack overflow, was found in the
unpacker for ZIP files. A specially crafted ZIP archive could cause
the Java Virtual Machine (JVM) to crash when opened. (CVE-2012-0501)

This erratum also upgrades the OpenJDK package to IcedTea6 1.10.6.
Refer to the NEWS file, linked to in the References, for further
information.

All users of java-1.6.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect.");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2012-March/002690.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.6.0-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-0507");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java AtomicReferenceArray Type Violation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-1.6.0.0-1.25.1.10.6.0.1.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.25.1.10.6.0.1.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.25.1.10.6.0.1.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.25.1.10.6.0.1.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.25.1.10.6.0.1.el5_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk / java-1.6.0-openjdk-demo / etc");
}
