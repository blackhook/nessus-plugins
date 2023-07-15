#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-ed735463e3.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103342);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-10664", "CVE-2017-12134", "CVE-2017-12135", "CVE-2017-12136", "CVE-2017-12137", "CVE-2017-12855", "CVE-2017-5579", "CVE-2017-7718", "CVE-2017-8309", "CVE-2017-8379", "CVE-2017-9330");
  script_xref(name:"FEDORA", value:"2017-ed735463e3");

  script_name(english:"Fedora 25 : xen (2017-ed735463e3)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Qemu: usb: ohci: infinite loop due to incorrect return value
[CVE-2017-9330] (#1457698) Qemu: qemu-nbd: server breaks with SIGPIPE
upon client abort [CVE-2017-10664] (#1466466) revised full fix for
XSA-226 (regressed 32-bit Dom0 or backend domains)

----

full fix for XSA-226, replacing workaround drop conflict of xendomain
and libvirtd as can cause problems (#1398590) add-to-physmap error
paths fail to release lock on ARM [XSA-235] (#1484476) Qemu: audio:
host memory leakage via capture buffer [CVE-2017-8309] (#1446521)
Qemu: input: host memory leakage via keyboard events [CVE-2017-8379]
(#1446561)

----

Qemu: serial: host memory leakage 16550A UART emulation
[CVE-2017-5579] (#1416162) Qemu: display: cirrus: OOB read access
issue [CVE-2017-7718] (#1443444) xen: various flaws (#1481765)
multiple problems with transitive grants [XSA-226, CVE-2017-12135]
x86: PV privilege escalation via map_grant_ref [XSA-227,
CVE-2017-12137] grant_table: Race conditions with maptrack free list
handling [XSA-228, CVE-2017-12136] grant_table: possibly premature
clearing of GTF_writing / GTF_reading [XSA-230, CVE-2017-12855]

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-ed735463e3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^25([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 25", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC25", reference:"xen-4.7.3-4.fc25")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
