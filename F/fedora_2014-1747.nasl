#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-1747.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72403);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"FEDORA", value:"2014-1747");

  script_name(english:"Fedora 20 : ikiwiki-3.20140125-1.fc20 (2014-1747)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to the latest stable version.

Changes in ikiwiki 3.20140125 :

  - inline: Allow overriding the title of the feed. Closes:
    http://bugs.debian.org/735123 Thanks, Christophe Rhodes

    - osm: Escape name parameter. Closes:
      http://bugs.debian.org/731797

Changes in ikiwiki 3.20140102 :

  - aggregate: Improve display of post author.

    - poll: Fix behavior of poll buttons when inlined.

    - Fixed unncessary tight loop hash copy in saveindex
      where a pointer can be used instead. Can speed up
      refreshes by nearly 50% in some circumstances.

    - Optimized loadindex by caching the page name in the
      index.

    - Added only_committed_changes config setting, which
      speeds up wiki refresh by querying git to find the
      files that were changed, rather than looking at the
      work tree. Not enabled by default as it can break some
      setups where not all files get committed to git.

    - comments: Write pending moderation comments to the
      transient underlay to avoid conflict with
      only_committed_changes.

    - search: Added google_search option, which makes it
      search google rather than using the internal xapain
      database. (googlesearch plugin is too hard to turn on
      when xapain databases corrupt themselves, which
      happens all too frequently).

    - osm: Remove invalid use of charset on embedded
      JavaScript tags. Closes: http://bugs.debian.org/731197

    - style.css: Add compatibility definitions for more
      block-level html5 elements. Closes:
      http://bugs.debian.org/731199

    - aggregate: Fix several bugs in handling of empty and
      colliding titles when generating filenames.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://bugs.debian.org/731197
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=731197"
  );
  # http://bugs.debian.org/731199
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=731199"
  );
  # http://bugs.debian.org/731797
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=731797"
  );
  # http://bugs.debian.org/735123
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=735123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1039938"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-February/128020.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0f40e40e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ikiwiki package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ikiwiki");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"ikiwiki-3.20140125-1.fc20")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ikiwiki");
}
