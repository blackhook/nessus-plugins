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
  script_id(95846);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-5160", "CVE-2015-5313", "CVE-2016-5008");

  script_name(english:"Scientific Linux Security Update : libvirt on SL7.x x86_64 (20161103)");
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
"The following packages have been upgraded to a newer upstream version:
libvirt (2.0.0).

Security Fix(es) :

  - It was found that the libvirt daemon, when using RBD
    (RADOS Block Device), leaked private credentials to the
    process list. A local attacker could use this flaw to
    perform certain privileged operations within the
    cluster. (CVE-2015-5160)

  - A path-traversal flaw was found in the way the libvirt
    daemon handled filesystem names for storage volumes. A
    libvirt user with privileges to create storage volumes
    and without privileges to create and modify domains
    could possibly use this flaw to escalate their
    privileges. (CVE-2015-5313)

  - It was found that setting a VNC password to an empty
    string in libvirt did not disable all access to the VNC
    server as documented, instead it allowed access with no
    authentication required. An attacker could use this flaw
    to access a VNC server with an empty VNC password
    without any authentication. (CVE-2016-5008)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1612&L=scientific-linux-errata&F=&S=&P=9310
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5dce02be"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-login-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/11");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-2.0.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-client-2.0.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-2.0.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-config-network-2.0.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-config-nwfilter-2.0.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-2.0.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-lxc-2.0.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-network-2.0.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-2.0.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-2.0.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-2.0.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-2.0.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-2.0.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-kvm-2.0.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-lxc-2.0.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-debuginfo-2.0.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-devel-2.0.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-docs-2.0.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-lock-sanlock-2.0.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-login-shell-2.0.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-nss-2.0.0-10.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-client / libvirt-daemon / etc");
}
