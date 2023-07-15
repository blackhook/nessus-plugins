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
  script_id(72197);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-6458", "CVE-2014-1447");

  script_name(english:"Scientific Linux Security Update : libvirt on SL6.x i386/x86_64 (20140128)");
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
"A use-after-free flaw was found in the way several libvirt block APIs
handled domain jobs. A remote attacker able to establish a read-only
connection to libvirtd could use this flaw to crash libvirtd or,
potentially, execute arbitrary code with the privileges of the
libvirtd process (usually root). (CVE-2013-6458)

A race condition was found in the way libvirtd handled keepalive
initialization requests when the connection was closed prior to
establishing connection credentials. An attacker able to establish a
read- only connection to libvirtd could use this flaw to crash
libvirtd, resulting in a denial of service. (CVE-2014-1447)

This update also fixes the following bug :

  - A race condition was possible between a thread starting
    a virtual machine with a guest agent configured (regular
    start-up or while migrating) and a thread that was
    killing the VM process (or the process crashing). The
    race could cause the monitor object to be freed by the
    thread that killed the VM process, which was later
    accessed by the thread that was attempting to start the
    VM, resulting in a crash. This issue was fixed by
    checking the state of the VM after the attempted
    connection to the guest agent; if the VM in the meantime
    exited, no other operations are attempted.

After installing the updated packages, libvirtd will be restarted
automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1401&L=scientific-linux-errata&T=0&P=1355
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f1b5f4d4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"libvirt-0.10.2-29.el6_5.3")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-client-0.10.2-29.el6_5.3")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-debuginfo-0.10.2-29.el6_5.3")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-devel-0.10.2-29.el6_5.3")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libvirt-lock-sanlock-0.10.2-29.el6_5.3")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-python-0.10.2-29.el6_5.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-client / libvirt-debuginfo / libvirt-devel / etc");
}
