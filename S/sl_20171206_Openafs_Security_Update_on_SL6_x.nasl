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
  script_id(105070);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_name(english:"Scientific Linux Security Update : Openafs Security Update on SL6.x, SL7.x i386/x86_64 (20171206)");
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

Security Fix(es) :

  - Certain values transmitted in RX ACK packets were not
    sanity checked by OpenAFS receiving peers, which could
    lead to an assertion being triggered during construction
    of outgoing packets on the same connection, resulting in
    server process crashes or client kernel panics."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1712&L=scientific-linux-errata&F=&S=&P=6984
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10b1b2e8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kmod-openafs-1.6-sl-693");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kmod-openafs-696");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-kpasswd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-module-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-plumbing-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-server");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"kmod-openafs-696-1.6.20-257.sl6.696")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-1.6.20-257.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-authlibs-1.6.20-257.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-authlibs-devel-1.6.20-257.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-client-1.6.20-257.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-compat-1.6.20-257.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-devel-1.6.20-257.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-kernel-source-1.6.20-257.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-kpasswd-1.6.20-257.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-krb5-1.6.20-257.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-module-tools-1.6.20-257.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-plumbing-tools-1.6.20-257.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-server-1.6.20-257.sl6")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kmod-openafs-1.6-sl-693-1.6.22-278.sl7.693.11.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-1.6.22-278.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-authlibs-1.6.22-278.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-authlibs-devel-1.6.22-278.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-client-1.6.22-278.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-compat-1.6.22-278.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-devel-1.6.22-278.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-kernel-source-1.6.22-278.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-kpasswd-1.6.22-278.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-krb5-1.6.22-278.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-module-tools-1.6.22-278.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-plumbing-tools-1.6.22-278.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-server-1.6.22-278.sl7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kmod-openafs-1.6-sl-693 / kmod-openafs-696 / openafs / etc");
}
