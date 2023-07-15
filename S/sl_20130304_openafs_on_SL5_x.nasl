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
  script_id(65021);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-1794", "CVE-2013-1795");

  script_name(english:"Scientific Linux Security Update : openafs on SL5.x SL6.x i386/x86_64 (20130304)");
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
"By carefully crafting an ACL entry an attacker may overflow fixed
length buffers within the OpenAFS fileserver, crashing the fileserver,
and potentially permitting the execution of arbitrary code. To perform
the exploit, the attacker must already have permissions to create ACLs
on the fileserver in question. Once such an ACL is present on a
fileserver, client utilities such as 'fs' which manipulate ACLs, may
be crashed when they attempt to read or modify the ACL.(CVE-2013-1794)

The ptserver accepts a list of unbounded size from the IdToName RPC.
The length of this list is then used to determine the size of a number
of other internal data structures. If the length is sufficiently large
then we may hit an integer overflow when calculating the size to pass
to malloc, and allocate data structures of insufficient length,
allowing heap memory to be overwritten. This may allow an
unauthenticated attacker to crash an OpenAFS ptserver. (CVE-2013-1795)

Scientific Linux 5 users must also update to at least
kernel-2.6.18-308.20.1.el5 to receive a compatible kernel module.

Scientific Linux 6 users must also update to at least
kernel-2.6.32-279.el6 to avoid issues with system stability. Any
32-bit SL6 system should be aware of possible problems with the afs
cache when switching from kernels prior to kernel-2.6.32-279.el6.
Purging your OpenAFS cache seems to resolve this issue.

After installing the update, OpenAFS services must be restarted for
the changes to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1303&L=scientific-linux-errata&T=0&P=76
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?099f228b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-308.20.1.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-308.20.1.el5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-308.20.1.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-308.20.1.el5PAE-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-308.20.1.el5xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-308.20.1.el5xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-308.24.1.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-308.24.1.el5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-308.24.1.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-308.24.1.el5PAE-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-308.24.1.el5xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-308.24.1.el5xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-348.1.1.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-348.1.1.el5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-348.1.1.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-348.1.1.el5PAE-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-348.1.1.el5xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-348.1.1.el5xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-348.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-348.el5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-348.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-348.el5PAE-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-348.el5xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-module-openafs-2.6.18-348.el5xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kmod-openafs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-authlibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-authlibs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-kpasswd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-plumbing-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openafs-server");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-308.20.1.el5-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-308.20.1.el5-debuginfo-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-308.20.1.el5PAE-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-308.20.1.el5PAE-debuginfo-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-308.20.1.el5xen-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-308.20.1.el5xen-debuginfo-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-308.24.1.el5-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-308.24.1.el5-debuginfo-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-308.24.1.el5PAE-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-308.24.1.el5PAE-debuginfo-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-308.24.1.el5xen-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-308.24.1.el5xen-debuginfo-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-348.1.1.el5-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-348.1.1.el5-debuginfo-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-348.1.1.el5PAE-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-348.1.1.el5PAE-debuginfo-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-348.1.1.el5xen-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-348.1.1.el5xen-debuginfo-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-348.el5-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-348.el5-debuginfo-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-348.el5PAE-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-348.el5PAE-debuginfo-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-348.el5xen-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-348.el5xen-debuginfo-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-authlibs-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-authlibs-devel-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-client-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-compat-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-debug-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-debuginfo-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-devel-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-kernel-source-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-kpasswd-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-krb5-1.4.14-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"openafs-server-1.4.14-82.sl5")) flag++;

if (rpm_check(release:"SL6", reference:"kmod-openafs-1.6.1-114.sl6.71")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-1.6.1-114.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-authlibs-1.6.1-114.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-authlibs-devel-1.6.1-114.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-client-1.6.1-114.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-compat-1.6.1-114.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-devel-1.6.1-114.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-kernel-source-1.6.1-114.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-kpasswd-1.6.1-114.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-krb5-1.6.1-114.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-plumbing-tools-1.6.1-114.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"openafs-server-1.6.1-114.sl6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-module-openafs-2.6.18-308.20.1.el5 / etc");
}
