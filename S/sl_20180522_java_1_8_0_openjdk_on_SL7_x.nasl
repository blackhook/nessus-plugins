#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(110023);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2018-3639");

  script_name(english:"Scientific Linux Security Update : java-1.8.0-openjdk on SL7.x x86_64 (20180522) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Security Fix(es) :

  - An industry-wide issue was found in the way many modern
    microprocessor designs have implemented speculative
    execution of Load &amp; Store instructions (a commonly
    used performance optimization). It relies on the
    presence of a precisely-defined instruction sequence in
    the privileged code as well as the fact that memory read
    from address to which a recent memory write has occurred
    may see an older value and subsequently cause an update
    into the microprocessor's data cache even for
    speculatively executed instructions that never actually
    commit (retire). As a result, an unprivileged attacker
    could use this flaw to read privileged memory by
    conducting targeted cache side-channel attacks.
    (CVE-2018-3639)

Note: This is the OpenJDK side of the CVE-2018-3639 mitigation."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1805&L=scientific-linux-errata&F=&S=&P=25462
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c1d3bdc7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-accessibility-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-javadoc-zip-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/23");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-1.8.0.171-8.b10.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-1.8.0.171-8.b10.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-debug-1.8.0.171-8.b10.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-debug-1.8.0.171-8.b10.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.171-8.b10.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-1.8.0.171-8.b10.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.171-8.b10.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-1.8.0.171-8.b10.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.171-8.b10.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-1.8.0.171-8.b10.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.171-8.b10.el7_5")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.8.0-openjdk-javadoc-1.8.0.171-8.b10.el7_5")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.171-8.b10.el7_5")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.8.0-openjdk-javadoc-zip-1.8.0.171-8.b10.el7_5")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.8.0-openjdk-javadoc-zip-debug-1.8.0.171-8.b10.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-1.8.0.171-8.b10.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-debug-1.8.0.171-8.b10.el7_5")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk / java-1.8.0-openjdk-accessibility / etc");
}
