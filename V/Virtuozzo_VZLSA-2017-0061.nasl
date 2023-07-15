#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101406);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2016-5542",
    "CVE-2016-5554",
    "CVE-2016-5573",
    "CVE-2016-5582",
    "CVE-2016-5597"
  );

  script_name(english:"Virtuozzo 7 : java-1.6.0-openjdk / java-1.6.0-openjdk-demo / etc (VZLSA-2017-0061)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for java-1.6.0-openjdk is now available for Red Hat
Enterprise Linux 5, Red Hat Enterprise Linux 6, and Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The java-1.6.0-openjdk packages provide the OpenJDK 6 Java Runtime
Environment and the OpenJDK 6 Java Software Development Kit.

Security Fix(es) :

* It was discovered that the Hotspot component of OpenJDK did not
properly check arguments of the System.arraycopy() function in certain
cases. An untrusted Java application or applet could use this flaw to
corrupt virtual machine's memory and completely bypass Java sandbox
restrictions. (CVE-2016-5582)

* It was discovered that the Hotspot component of OpenJDK did not
properly check received Java Debug Wire Protocol (JDWP) packets. An
attacker could possibly use this flaw to send debugging commands to a
Java program running with debugging enabled if they could make
victim's browser send HTTP requests to the JDWP port of the debugged
application. (CVE-2016-5573)

* It was discovered that the Libraries component of OpenJDK did not
restrict the set of algorithms used for Jar integrity verification.
This flaw could allow an attacker to modify content of the Jar file
that used weak signing key or hash algorithm. (CVE-2016-5542)

Note: After this update, MD2 hash algorithm and RSA keys with less
than 1024 bits are no longer allowed to be used for Jar integrity
verification by default. MD5 hash algorithm is expected to be disabled
by default in the future updates. A newly introduced security property
jdk.jar.disabledAlgorithms can be used to control the set of disabled
algorithms.

* A flaw was found in the way the JMX component of OpenJDK handled
classloaders. An untrusted Java application or applet could use this
flaw to bypass certain Java sandbox restrictions. (CVE-2016-5554)

* A flaw was found in the way the Networking component of OpenJDK
handled HTTP proxy authentication. A Java application could possibly
expose HTTPS server authentication credentials via a plain text
network connection to an HTTP proxy if proxy asked for authentication.
(CVE-2016-5597)

Note: After this update, Basic HTTP proxy authentication can no longer
be used when tunneling HTTPS connection through an HTTP proxy. Newly
introduced system properties jdk.http.auth.proxying.disabledSchemes
and jdk.http.auth.tunneling.disabledSchemes can be used to control
which authentication schemes can be requested by an HTTP proxy when
proxying HTTP and HTTPS connections respectively.

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2017-0061.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?137c3952");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017-0061");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.6.0-openjdk / java-1.6.0-openjdk-demo / etc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = pregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 7.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["java-1.6.0-openjdk-1.6.0.41-1.13.13.1.vl7",
        "java-1.6.0-openjdk-demo-1.6.0.41-1.13.13.1.vl7",
        "java-1.6.0-openjdk-devel-1.6.0.41-1.13.13.1.vl7",
        "java-1.6.0-openjdk-javadoc-1.6.0.41-1.13.13.1.vl7",
        "java-1.6.0-openjdk-src-1.6.0.41-1.13.13.1.vl7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-7", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk / java-1.6.0-openjdk-demo / etc");
}
