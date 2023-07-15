#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:0986 and 
# Oracle Linux Security Advisory ELSA-2015-0986 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(83401);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-0267");
  script_bugtraq_id(74622);
  script_xref(name:"RHSA", value:"2015:0986");

  script_name(english:"Oracle Linux 7 : kexec-tools (ELSA-2015-0986)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:0986 :

Updated kexec-tools packages that fix one security issue, one bug, and
add one enhancement are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The kexec-tools packages contain the /sbin/kexec binary and utilities
that together form the user-space component of the kernel's kexec
feature. The /sbin/kexec binary facilitates a new kernel to boot using
the kernel's kexec feature either on a normal or a panic reboot. The
kexec fastboot mechanism allows booting a Linux kernel from the
context of an already running kernel.

It was found that the module-setup.sh script provided by kexec-tools
created temporary files in an insecure way. A malicious, local user
could use this flaw to conduct a symbolic link attack, allowing them
to overwrite the contents of arbitrary files. (CVE-2015-0267)

This issue was discovered by Harald Hoyer of Red Hat.

This update also fixes the following bug :

* On Red Hat Enterprise Linux Atomic Host systems, the kdump tool
previously saved kernel crash dumps in the /sysroot/crash file instead
of the /var/crash file. The parsing error that caused this problem has
been fixed, and the kernel crash dumps are now correctly saved in
/var/crash. (BZ#1206464)

In addition, this update adds the following enhancement :

* The makedumpfile command now supports the new sadump format that can
represent more than 16 TB of physical memory space. This allows users
of makedumpfile to read dump files over 16 TB, generated by sadump on
certain upcoming server models. (BZ#1208753)

All kexec-tools users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues and
add this enhancement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-May/005043.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kexec-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kexec-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kexec-tools-anaconda-addon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kexec-tools-eppic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kexec-tools-2.0.7-19.0.1.el7_1.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kexec-tools-anaconda-addon-2.0.7-19.0.1.el7_1.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kexec-tools-eppic-2.0.7-19.0.1.el7_1.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kexec-tools / kexec-tools-anaconda-addon / kexec-tools-eppic");
}