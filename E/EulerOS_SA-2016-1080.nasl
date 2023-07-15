#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99840);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2016-5542",
    "CVE-2016-5554",
    "CVE-2016-5573",
    "CVE-2016-5582",
    "CVE-2016-5597"
  );

  script_name(english:"EulerOS 2.0 SP1 : java-1.7.0-openjdk (EulerOS-SA-2016-1080)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the java-1.7.0-openjdk packages
installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - It was discovered that the Libraries component of
    OpenJDK did not restrict the set of algorithms used for
    JAR integrity verification. This flaw could allow an
    attacker to modify content of the JAR file that used
    weak signing key or hash algorithm.(CVE-2016-5542)

  - A flaw was found in the way the JMX component of
    OpenJDK handled classloaders. An untrusted Java
    application or applet could use this flaw to bypass
    certain Java sandbox restrictions.(CVE-2016-5554)

  - It was discovered that the Hotspot component of OpenJDK
    did not properly check received Java Debug Wire
    Protocol (JDWP) packets. An attacker could possibly use
    this flaw to send debugging commands to a Java program
    running with debugging enabled if they could make
    victim's browser send HTTP requests to the JDWP port of
    the debugged application.(CVE-2016-5573)

  - It was discovered that the Hotspot component of OpenJDK
    did not properly check arguments of the
    System.arraycopy() function in certain cases. An
    untrusted Java application or applet could use this
    flaw to corrupt virtual machine's memory and completely
    bypass Java sandbox restrictions.(CVE-2016-5582)

  - A flaw was found in the way the Networking component of
    OpenJDK handled HTTP proxy authentication. A Java
    application could possibly expose HTTPS server
    authentication credentials via a plain text network
    connection to an HTTP proxy if proxy asked for
    authentication.(CVE-2016-5597)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1080
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?777fda6d");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.7.0-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.7.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["java-1.7.0-openjdk-1.7.0.121-2.6.8.0",
        "java-1.7.0-openjdk-devel-1.7.0.121-2.6.8.0",
        "java-1.7.0-openjdk-headless-1.7.0.121-2.6.8.0"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk");
}
