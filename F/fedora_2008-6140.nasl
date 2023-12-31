#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-6140.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(34421);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2008-2374");
  script_bugtraq_id(30105);
  script_xref(name:"FEDORA", value:"2008-6140");

  script_name(english:"Fedora 8 : bluez-libs-3.35-1.fc8 / bluez-utils-3.35-3.fc8 (2008-6140)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Fedora host is missing one or more security updates :

bluez-utils-3.35-3.fc8 :

  - Thu Jul 10 2008 - Will Woods <wwoods at redhat.com> -
    3.35-3

    - Re-add hid2hci

    - Fri Jul 4 2008 - Bastien Nocera <bnocera at
      redhat.com> - 3.35-2

    - Re-add hidd

    - Thu Jul 3 2008 - Bastien Nocera <bnocera at
      redhat.com> - 3.35-1

    - Update to 3.35

    - Fri Jun 27 2008 - Bastien Nocera <bnocera at
      redhat.com> - 3.34-1

    - Update to 3.34

    - Wed Mar 26 2008 - Bastien Nocera <bnocera at
      redhat.com> - 3.20-7

    - Add patch to avoid a kernel oops when switching from
      HID to HCI mode (#228755)

  - Fri Jan 25 2008 - Bastien Nocera <bnocera at redhat.com>
    - 3.20-6

    - Avoid dund and pand starting too early (#429489)

    - Fri Jan 25 2008 - Bastien Nocera <bnocera at
      redhat.com> - 3.20-5

    - Fix hcid trying to find the OUI file somewhere in /var
      (#428803)

bluez-libs-3.35-1.fc8 :

  - Thu Jul 3 2008 - Bastien Nocera <bnocera at redhat.com>
    - 3.35-1

    - Update to 3.35

    - Fri Jun 27 2008 - Bastien Nocera <bnocera at
      redhat.com> - 3.34-1

    - Update to 3.34

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452715"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-October/015336.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?62f1315e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-October/015337.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3177f5b5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bluez-libs and / or bluez-utils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bluez-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bluez-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
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
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 8.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC8", reference:"bluez-libs-3.35-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"bluez-utils-3.35-3.fc8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bluez-libs / bluez-utils");
}
