#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(117472);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_name(english:"Scientific Linux Security Update : Moderate: OpenAFS on SL6.x, SL7.x i386/x86_64 (20180911)");
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
"These releases include fixes for three security advisories,
OPENAFS-SA-2018-001, OPENAFS-SA-2018-002, and OPENAFS-SA-2018-003.

OPENAFS-SA-2018-001 only affects deployments that run the 'butc'
utility as part of the in-tree backup system, but is of high severity
for those sites which are affected -- an anonymous attacker could
replace entire volumes with attacker-controlled contents.

OPENAFS-SA-2018-002 is for information leakage over the network via
uninitialized RPC output variables. A number of RPCs are affected,
some of which require the caller to be authenticated, but in some
cases hundreds of bytes of data can be leaked per call. Of note is
that cache managers are also subject to (kernel) memory leakage via
AFSCB_ RPCs.

OPENAFS-SA-2018-003 is a denial of service whereby anonymous attackers
can cause server processes to consume large quantities of memory for a
sustained period of time.

The changes to fix OPENAFS-SA-2018-001 require behavior change in both
butc(8) and backup(8) to use authenticated connections; old and new
versions of these utilities will not interoperate absent specific
configuration of the new tool to use the old (insecure) behavior.
These changes also are expected to cause backup(8)'s interactive mode
to be limited to only butc connections requiring (or not requiring)
authentication within a given interactive session, based on the
initial arguments selected."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1809&L=scientific-linux-errata&F=&S=&P=470
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e7829dd2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kmod-openafs-1.6-sl-862");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kmod-openafs-1.6-sl-862-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kmod-openafs-754");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-1.6-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-1.6-sl-authlibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-1.6-sl-authlibs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-1.6-sl-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-1.6-sl-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-1.6-sl-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-kpasswd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-module-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-plumbing-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-server");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"kmod-openafs-754-1.6.23-289.sl6.754.3.5")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-1.6.23-289.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-authlibs-1.6.23-289.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-authlibs-devel-1.6.23-289.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-client-1.6.23-289.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-compat-1.6.23-289.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-debuginfo-1.6.23-289.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-devel-1.6.23-289.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-kernel-source-1.6.23-289.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-kpasswd-1.6.23-289.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-krb5-1.6.23-289.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-module-tools-1.6.23-289.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-plumbing-tools-1.6.23-289.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-server-1.6.23-289.sl6")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kmod-openafs-1.6-sl-862-1.6.23-289.sl7.862.11.6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kmod-openafs-1.6-sl-862-debuginfo-1.6.23-289.sl7.862.11.6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-1.6.23-289.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-authlibs-1.6.23-289.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-authlibs-devel-1.6.23-289.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-client-1.6.23-289.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-compat-1.6.23-289.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-debuginfo-1.6.23-289.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-devel-1.6.23-289.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-kernel-source-1.6.23-289.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-kpasswd-1.6.23-289.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-krb5-1.6.23-289.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-module-tools-1.6.23-289.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-plumbing-tools-1.6.23-289.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openafs-1.6-sl-server-1.6.23-289.sl7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kmod-openafs-1.6-sl-862 / kmod-openafs-1.6-sl-862-debuginfo / etc");
}
