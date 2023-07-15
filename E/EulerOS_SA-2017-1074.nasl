#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99940);
  script_version("3.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-3509",
    "CVE-2017-3511",
    "CVE-2017-3526",
    "CVE-2017-3533",
    "CVE-2017-3539",
    "CVE-2017-3544"
  );

  script_name(english:"EulerOS 2.0 SP2 : java-1.8.0-openjdk (EulerOS-SA-2017-1074)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the java-1.8.0-openjdk packages
installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - An untrusted library search path flaw was found in the
    JCE component of OpenJDK. A local attacker could
    possibly use this flaw to cause a Java application
    using JCE to load an attacker-controlled library and
    hence escalate their privileges. (CVE-2017-3511)

  - It was found that the JAXP component of OpenJDK failed
    to correctly enforce parse tree size limits when
    parsing XML document. An attacker able to make a Java
    application parse a specially crafted XML document
    could use this flaw to make it consume an excessive
    amount of CPU and memory. (CVE-2017-3526)

  - It was discovered that the HTTP client implementation
    in the Networking component of OpenJDK could cache and
    re-use an NTLM authenticated connection in a different
    security context. A remote attacker could possibly use
    this flaw to make a Java application perform HTTP
    requests authenticated with credentials of a different
    user. (CVE-2017-3509)

  - It was discovered that the Security component of
    OpenJDK did not allow users to restrict the set of
    algorithms allowed for Jar integrity verification. This
    flaw could allow an attacker to modify content of the
    Jar file that used weak signing key or hash algorithm.
    (CVE-2017-3539)

  - Newline injection flaws were discovered in FTP and SMTP
    client implementations in the Networking component in
    OpenJDK. A remote attacker could possibly use these
    flaws to manipulate FTP or SMTP connections established
    by a Java application. (CVE-2017-3533, CVE-2017-3544)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1074
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ee2409a");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.8.0-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.8.0-openjdk-headless");
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
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["java-1.8.0-openjdk-1.8.0.131-2.b11",
        "java-1.8.0-openjdk-devel-1.8.0.131-2.b11",
        "java-1.8.0-openjdk-headless-1.8.0.131-2.b11"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk");
}
