#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-0450.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51853);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2011-0444", "CVE-2011-0445");
  script_xref(name:"FEDORA", value:"2011-0450");

  script_name(english:"Fedora 14 : wireshark-1.4.3-1.fc14 (2011-0450)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Mon Jan 17 2011 Jan Safranek <jsafrane at redhat.com> -
    1.4.2-3

    - upgrade to 1.4.3

    - see
      http://www.wireshark.org/docs/relnotes/wireshark-1.4.3
      .html

    - Wed Jan 5 2011 Jan Safranek <jsafrane at redhat.com> -
      1.4.2-2

    - fixed buffer overflow in ENTTEC dissector (#666897)

    - Mon Nov 22 2010 Jan Safranek <jsafrane at redhat.com>
      - 1.4.2-1

    - upgrade to 1.4.2

    - see
      http://www.wireshark.org/docs/relnotes/wireshark-1.4.2
      .html

    - Mon Nov 1 2010 Jan Safranek <jsafrane at redhat.com> -
      1.4.1-2

    - temporarily disable zlib until
      https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=49
      55 is resolved (#643461)

  - Fri Oct 22 2010 Jan Safranek <jsafrane at redhat.com> -
    1.4.1-1

    - upgrade to 1.4.1

    - see
      http://www.wireshark.org/docs/relnotes/wireshark-1.4.1
      .html

    - Own the %{_libdir}/wireshark dir (#644508)

    - associate *.pcap files with wireshark (#641163)

    - Tue Oct 5 2010 jkeating - 1.4.0-2.1

    - Rebuilt for gcc bug 634757

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.wireshark.org/docs/relnotes/wireshark-1.4.1.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-1.4.1.html"
  );
  # http://www.wireshark.org/docs/relnotes/wireshark-1.4.2.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-1.4.2.html"
  );
  # http://www.wireshark.org/docs/relnotes/wireshark-1.4.3.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-1.4.3.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=4955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=669441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=669443"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-February/053650.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b9eccaec"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"wireshark-1.4.3-1.fc14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");
}
