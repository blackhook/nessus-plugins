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
  script_id(95852);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-7035");

  script_name(english:"Scientific Linux Security Update : pacemaker on SL7.x x86_64 (20161103)");
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

  - An authorization flaw was found in Pacemaker, where it
    did not properly guard its IPC interface. An attacker
    with an unprivileged account on a Pacemaker node could
    use this flaw to, for example, force the Local Resource
    Manager daemon to execute a script as root and thereby
    gain root access on the machine. (CVE-2016-7035)

Bug Fix(es) :

  - The version of Pacemaker in Scientific Linux 7.3
    incorporated an increase in the version number of the
    remote node protocol. Consequently, cluster nodes
    running Pacemaker in Scientific Linux 7.3 and remote
    nodes running earlier versions of Scientific Linux were
    not able to communicate with each other unless special
    precautions were taken. This update preserves the
    rolling upgrade capability."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1612&L=scientific-linux-errata&F=&S=&P=1035
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a90da07d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pacemaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pacemaker-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pacemaker-cluster-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pacemaker-cts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pacemaker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pacemaker-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pacemaker-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pacemaker-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pacemaker-nagios-plugins-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pacemaker-remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/15");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-cli-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-cluster-libs-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-cts-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-debuginfo-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-doc-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-libs-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-libs-devel-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-nagios-plugins-metadata-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pacemaker-remote-1.1.15-11.el7_3.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pacemaker / pacemaker-cli / pacemaker-cluster-libs / pacemaker-cts / etc");
}
