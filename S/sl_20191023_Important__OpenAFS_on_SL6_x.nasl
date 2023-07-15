#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(130191);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_name(english:"Scientific Linux Security Update : Important: OpenAFS on SL6.x, SL7.x i386/x86_64 (20191023)");
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
"Security Fixes :

  - Fix OPENAFS-SA-2019-001: information leakage in failed
    RPC output Generated RPC handler routines ran output
    variables through XDR encoding even when the call had
    failed and would shortly be aborted (and for which
    uninitialized output variables is common); any complete
    packets assembled in the process would be sent to the
    peer, leaking the contents of the uninitialized memory
    in question.

  - Fix OPENAFS-SA-2019-002: information leakage from
    uninitialized scalars Generated RPC handler routines did
    not initialize output variables of scalar (fixed-length)
    type, since they did not require dedicated logic to
    free. Such variables allocated on the stack could remain
    uninitialized in some cases (including those affected by
    OPENAFS-SA-2019-001), and the contents of uninitialized
    memory would be returned to the peer."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1910&L=SCIENTIFIC-LINUX-ERRATA&P=9240
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1061ef5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kmod-openafs-1.6-sl-1062");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kmod-openafs-1.6-sl-1062-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kmod-openafs-754");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kmod-openafs-754-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"kmod-openafs-754-1.6.24-290.sl6.754.23.1")) flag++;
if (rpm_check(release:"SL6", reference:"kmod-openafs-754-debuginfo-1.6.24-290.sl6.754.23.1")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kmod-openafs-1.6-sl-1062-1.6.24-290.sl7.1062.4.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kmod-openafs-1.6-sl-1062-debuginfo-1.6.24-290.sl7.1062.4.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kmod-openafs-1.6-sl-1062 / kmod-openafs-1.6-sl-1062-debuginfo / etc");
}
