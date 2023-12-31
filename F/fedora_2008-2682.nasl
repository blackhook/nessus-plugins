#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-2682.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(31691);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237", "CVE-2008-1238", "CVE-2008-1241");
  script_bugtraq_id(28448);
  script_xref(name:"FEDORA", value:"2008-2682");

  script_name(english:"Fedora 8 : Miro-1.1.2-2.fc8 / blam-1.8.3-14.fc8 / chmsee-1.0.0-1.30.fc8 / devhelp-0.16.1-6.fc8 / etc (2008-2682)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox is an open source Web browser. Several flaws were
found in the processing of some malformed web content. A web page
containing such malicious content could cause Firefox to crash or,
potentially, execute arbitrary code as the user running Firefox.
(CVE-2008-1233, CVE-2008-1235, CVE-2008-1236, CVE-2008-1237) Several
flaws were found in the display of malformed web content. A web page
containing specially crafted content could, potentially, trick a
Firefox user into surrendering sensitive information. (CVE-2008-1234,
CVE-2008-1238, CVE-2008-1241) All Firefox users should upgrade to
these updated packages, which correct these issues, and are rebuilt
against the update Firefox packages.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=438713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=438715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=438717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=438718"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=438721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=438724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=438730"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008916.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?124ff337"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008917.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc225e0f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008918.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5eb16446"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008919.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9a7931b1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008920.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b92e55b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008921.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d277b67b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008922.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0b464a5e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008923.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ba623227"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008924.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1dbbd22"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008925.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb511dd2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008926.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d5e13b73"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008927.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b073bb58"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008928.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f86540d4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008929.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?991ecef2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008930.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97326ca9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008931.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?453f0aee"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(59, 79, 94, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Miro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:blam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chmsee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-web-photo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gtkmozembedmm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kazehakase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:liferea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvrml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnome2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"FC8", reference:"Miro-1.1.2-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"blam-1.8.3-14.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"chmsee-1.0.0-1.30.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"devhelp-0.16.1-6.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"epiphany-2.20.3-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"epiphany-extensions-2.20.1-6.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"firefox-2.0.0.13-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"galeon-2.0.4-1.fc8.3")) flag++;
if (rpm_check(release:"FC8", reference:"gnome-python2-extras-2.19.1-13.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gnome-web-photo-0.3-9.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gtkmozembedmm-1.4.2.cvs20060817-19.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"kazehakase-0.5.3-5.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"liferea-1.4.13-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"openvrml-0.17.5-4.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"ruby-gnome2-0.16.0-21.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"yelp-2.20.0-8.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Miro / blam / chmsee / devhelp / epiphany / epiphany-extensions / etc");
}
