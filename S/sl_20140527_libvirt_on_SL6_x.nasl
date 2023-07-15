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
  script_id(74209);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-0179");

  script_name(english:"Scientific Linux Security Update : libvirt on SL6.x i386/x86_64 (20140527)");
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
"It was found that libvirt passes the XML_PARSE_NOENT flag when parsing
XML documents using the libxml2 library, in which case all XML
entities in the parsed documents are expanded. A user able to force
libvirtd to parse an XML document with an entity pointing to a special
file that blocks on read access could use this flaw to cause libvirtd
to hang indefinitely, resulting in a denial of service on the system.
(CVE-2014-0179)

This update also fixes the following bugs :

  - When hot unplugging a virtual CPU (vCPU), libvirt kept a
    pointer to already freed memory if the vCPU was pinned
    to a host CPU. Consequently, when reading the CPU
    pinning information, libvirt terminated unexpectedly due
    to an attempt to access this memory. This update ensures
    that libvirt releases the pointer to the previously
    allocated memory when a vCPU is being hot unplugged, and
    it no longer crashes in this situation.

  - Previously, libvirt passed an incorrect argument to the
    'tc' command when setting quality of service (QoS) on a
    network interface controller (NIC). As a consequence,
    QoS was applied only to IP traffic. With this update,
    libvirt constructs the 'tc' command correctly so that
    QoS is applied to all traffic as expected.

  - When using the sanlock daemon for managing access to
    shared storage, libvirt expected all QEMU domains to be
    registered with sanlock. However, if a QEMU domain was
    started prior to enabling sanlock, the domain was not
    registered with sanlock. Consequently, migration of a
    virtual machine (VM) from such a QEMU domain failed with
    a libvirt error. With this update, libvirt verifies
    whether a QEMU domain process is registered with sanlock
    before it starts working with the domain, ensuring that
    migration of virtual machines works as expected.

After installing the updated packages, libvirtd will be restarted
automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1405&L=scientific-linux-errata&T=0&P=1155
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3bebc04a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/28");
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
if (rpm_check(release:"SL6", reference:"libvirt-0.10.2-29.el6_5.8")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-client-0.10.2-29.el6_5.8")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-debuginfo-0.10.2-29.el6_5.8")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-devel-0.10.2-29.el6_5.8")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"libvirt-lock-sanlock-0.10.2-29.el6_5.8")) flag++;
if (rpm_check(release:"SL6", reference:"libvirt-python-0.10.2-29.el6_5.8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-client / libvirt-debuginfo / libvirt-devel / etc");
}
