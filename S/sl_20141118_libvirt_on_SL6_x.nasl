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
  script_id(79331);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-3633", "CVE-2014-3657", "CVE-2014-7823");

  script_name(english:"Scientific Linux Security Update : libvirt on SL6.x i386/x86_64 (20141118)");
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
"An out-of-bounds read flaw was found in the way libvirt's
qemuDomainGetBlockIoTune() function looked up the disk index in a non-
persistent (live) disk configuration while a persistent disk
configuration was being indexed. A remote attacker able to establish a
read-only connection to libvirtd could use this flaw to crash libvirtd
or, potentially, leak memory from the libvirtd process.
(CVE-2014-3633)

A denial of service flaw was found in the way libvirt's
virConnectListAllDomains() function computed the number of used
domains. A remote attacker able to establish a read-only connection to
libvirtd could use this flaw to make any domain operations within
libvirt unresponsive. (CVE-2014-3657)

It was found that when the VIR_DOMAIN_XML_MIGRATABLE flag was used,
the QEMU driver implementation of the virDomainGetXMLDesc() function
could bypass the restrictions of the VIR_DOMAIN_XML_SECURE flag. A
remote attacker able to establish a read-only connection to libvirtd
could use this flaw to leak certain limited information from the
domain XML data. (CVE-2014-7823)

This update also fixes the following bug :

When dumping migratable XML configuration of a domain, libvirt removes
some automatically added devices for compatibility with older libvirt
releases. If such XML is passed to libvirt as a domain XML that should
be used during migration, libvirt checks this XML for compatibility
with the internally stored configuration of the domain. However, prior
to this update, these checks failed because of devices that were
missing (the same devices libvirt removed). As a consequence,
migration with user-supplied migratable XML failed. Since this feature
is used by OpenStack, migrating QEMU/KVM domains with OpenStack always
failed. With this update, before checking domain configurations for
compatibility, libvirt transforms both user-supplied and internal
configuration into a migratable form (automatically added devices are
removed) and checks those instead. Thus, no matter whether the
user-supplied configuration was generated as migratable or not,
libvirt does not err about missing devices, and migration succeeds as
expected.

After installing the updated packages, libvirtd will be restarted
automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1411&L=scientific-linux-errata&T=0&P=3675
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?69def905"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/19");
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
if (rpm_check(release:"SL6", reference:"libvirt-0.10.2-46.el6_6.2")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-client-0.10.2-46.el6_6.2")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-debuginfo-0.10.2-46.el6_6.2")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-devel-0.10.2-46.el6_6.2")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libvirt-lock-sanlock-0.10.2-46.el6_6.2")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-python-0.10.2-46.el6_6.2")) flag++;


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
