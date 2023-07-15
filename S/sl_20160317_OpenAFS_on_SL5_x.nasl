#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90020);
  script_version("2.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-2860");

  script_name(english:"Scientific Linux Security Update : OpenAFS on SL5.x, SL6.x, SL7.x i386/x86_64 (20160317)");
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
"--

This release fixes the vulnerabilities tracked as OPENAFS-SA-2016-001
and OPENAFS-SA-2016-002.

OPENAFS-SA-2016-001 (CVE-2016-2860): Users from foreign Kerberos
realms can create groups as if they were administrators

OPENAFS-SA-2016-002: Information leakage over the network due to
uninitialized memory

For more details please see

<a
href='http://www.openafs.org/pages/security/OPENAFS-SA-2016-001.txt'
target='_blank'>http://www.openafs.org/pages/security/OPENAFS-SA-2016-
001.txt</a> <a
href='http://www.openafs.org/pages/security/OPENAFS-SA-2016-002.txt'
target='_blank'>http://www.openafs.org/pages/security/OPENAFS-SA-2016-
002.txt</a>"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1603&L=scientific-linux-errata&F=&S=&P=6681
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f3435b1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-406.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-406.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-406.el5xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kmod-openafs-1.6-sl-327");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kmod-openafs-573");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-1.6-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-1.6-sl-authlibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-1.6-sl-authlibs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-1.6-sl-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-1.6-sl-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-1.6-sl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-1.6-sl-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-1.6-sl-kpasswd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-1.6-sl-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-1.6-sl-module-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-1.6-sl-plumbing-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-1.6-sl-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-authlibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-authlibs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-kpasswd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-module-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-plumbing-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-server");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-406.el5-1.4.15-89.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-406.el5PAE-1.4.15-89.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-406.el5xen-1.4.15-89.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-1.4.15-89.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-authlibs-1.4.15-89.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-authlibs-devel-1.4.15-89.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-client-1.4.15-89.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-compat-1.4.15-89.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-debug-1.4.15-89.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-devel-1.4.15-89.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-kernel-source-1.4.15-89.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-kpasswd-1.4.15-89.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-krb5-1.4.15-89.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-server-1.4.15-89.sl5")) flag++;

if (rpm_check(release:"SL6", reference:"kmod-openafs-573-1.6.17-234.sl6.573.12.1")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-1.6.17-234.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-authlibs-1.6.17-234.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-authlibs-devel-1.6.17-234.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-client-1.6.17-234.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-compat-1.6.17-234.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-devel-1.6.17-234.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-kernel-source-1.6.17-234.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-kpasswd-1.6.17-234.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-krb5-1.6.17-234.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-module-tools-1.6.17-234.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-plumbing-tools-1.6.17-234.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-server-1.6.17-234.sl6")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kmod-openafs-1.6-sl-327-1.6.17-234.sl7.327.10.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-1.6.17-234.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-authlibs-1.6.17-234.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-authlibs-devel-1.6.17-234.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-client-1.6.17-234.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-compat-1.6.17-234.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-devel-1.6.17-234.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-kernel-source-1.6.17-234.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-kpasswd-1.6.17-234.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-krb5-1.6.17-234.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-module-tools-1.6.17-234.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-plumbing-tools-1.6.17-234.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-server-1.6.17-234.sl7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-module-openafs-2.6.18-406.el5 / etc");
}
