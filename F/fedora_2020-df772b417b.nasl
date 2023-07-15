#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-df772b417b.
#

include("compat.inc");

if (description)
{
  script_id(144613);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-29479", "CVE-2020-29480", "CVE-2020-29481", "CVE-2020-29482", "CVE-2020-29483", "CVE-2020-29484", "CVE-2020-29485", "CVE-2020-29486", "CVE-2020-29566", "CVE-2020-29570", "CVE-2020-29571");
  script_xref(name:"FEDORA", value:"2020-df772b417b");
  script_xref(name:"IAVB", value:"2020-B-0077-S");

  script_name(english:"Fedora 32 : xen (2020-df772b417b)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"xenstore watch notifications lacking permission checks [XSA-115,
CVE-2020-29480] (#1908091) Xenstore: new domains inheriting existing
node permissions [XSA-322, CVE-2020-29481] (#1908095) Xenstore: wrong
path length check [XSA-323, CVE-2020-29482] (#1908096) Xenstore:
guests can crash xenstored via watchs [XSA-324, CVE-2020-29484]
(#1908088) Xenstore: guests can disturb domain cleanup [XSA-325,
CVE-2020-29483] (#1908087) oxenstored memory leak in reset_watches
[XSA-330, CVE-2020-29485] (#1908000) undue recursion in x86 HVM
context switch code [XSA-348, CVE-2020-29566] (#1908085) oxenstored:
node ownership can be changed by unprivileged clients [XSA-352,
CVE-2020-29486] (#1908003) oxenstored: permissions not checked on root
node [XSA-353, CVE-2020-29479] (#1908002) FIFO event channels control
block related ordering [XSA-358, CVE-2020-29570] (#1907931) FIFO event
channels control structure ordering [XSA-359, CVE-2020-29571]
(#1908089)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-df772b417b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:32");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/28");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^32([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 32", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC32", reference:"xen-4.13.2-5.fc32")) flag++;


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
