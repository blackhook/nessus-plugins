#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-9494.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40955);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2009-3070", "CVE-2009-3071", "CVE-2009-3072", "CVE-2009-3074", "CVE-2009-3075", "CVE-2009-3076", "CVE-2009-3077", "CVE-2009-3078", "CVE-2009-3079");
  script_bugtraq_id(36343);
  script_xref(name:"FEDORA", value:"2009-9494");

  script_name(english:"Fedora 10 : Miro-2.0.5-4.fc10 / blam-1.8.5-14.fc10 / epiphany-2.24.3-10.fc10 / etc (2009-9494)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Firefox version 3.0.14, fixing multiple
security issues detailed in the upstream advisories:
http://www.mozilla.org/security/known-
vulnerabilities/firefox30.html#firefox3.0.14 Update also includes all
packages depending on gecko-libs rebuilt against new version of
Firefox / XULRunner.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.mozilla.org/security/known-
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/known-"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=521686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=521687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=521688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=521690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=521691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=521692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=521693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=521694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=521695"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/028997.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f4998b84"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/028998.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8ac853b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/028999.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?245ae0fc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029000.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8cd1212b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029001.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf9185d8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029002.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?20a85e6c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029003.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e8cbcc4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029004.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a6498c6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029005.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9820b4c5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029006.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a209b2a1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029007.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?49f43a6d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029008.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8ef714c0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029009.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?80a7c0d3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029010.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?009387b3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029011.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1343564"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029012.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e881ce93"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029013.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a491f4c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029014.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?53747c5e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Miro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:blam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:evolution-rss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gecko-sharp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-web-photo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:google-gadgets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kazehakase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mugshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pcmanx-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Gtk2-MozEmbed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnome2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^10([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 10.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC10", reference:"Miro-2.0.5-4.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"blam-1.8.5-14.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"epiphany-2.24.3-10.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"epiphany-extensions-2.24.3-5.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"evolution-rss-0.1.4-3.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"firefox-3.0.14-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gecko-sharp2-0.13-12.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gnome-python2-extras-2.19.1-34.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gnome-web-photo-0.3-22.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"google-gadgets-0.10.5-10.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kazehakase-0.5.6-4.fc10.6")) flag++;
if (rpm_check(release:"FC10", reference:"mozvoikko-0.9.5-14.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"mugshot-1.2.2-13.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"pcmanx-gtk2-0.3.8-13.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"perl-Gtk2-MozEmbed-0.08-6.fc10.5")) flag++;
if (rpm_check(release:"FC10", reference:"ruby-gnome2-0.19.1-2.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"xulrunner-1.9.0.14-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"yelp-2.24.0-13.fc10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Miro / blam / epiphany / epiphany-extensions / evolution-rss / etc");
}
