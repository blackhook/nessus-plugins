#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(128237);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2019-3840");

  script_name(english:"Scientific Linux Security Update : libvirt on SL7.x x86_64 (20190806)");
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

  - libvirt: NULL pointer dereference after running
    qemuAgentCommand in qemuAgentGetInterfaces function
    (CVE-2019-3840)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1908&L=SCIENTIFIC-LINUX-ERRATA&P=33042
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71b0fafb"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-bash-completion");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-login-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/27");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-admin-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-bash-completion-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-client-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-config-network-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-config-nwfilter-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-lxc-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-network-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-core-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-disk-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-gluster-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-iscsi-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-logical-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-mpath-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-rbd-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-scsi-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-kvm-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-daemon-lxc-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-debuginfo-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-devel-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-docs-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-libs-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-lock-sanlock-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-login-shell-4.5.0-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvirt-nss-4.5.0-23.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-admin / libvirt-bash-completion / libvirt-client / etc");
}
