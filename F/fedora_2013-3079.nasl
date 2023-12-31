#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-3079.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65532);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2013-1620");
  script_bugtraq_id(57777);
  script_xref(name:"FEDORA", value:"2013-3079");

  script_name(english:"Fedora 17 : nspr-4.9.5-2.fc17 / nss-3.14.3-1.fc17 / nss-softokn-3.14.3-1.fc17 / etc (2013-3079)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to nss-3.14.3

This is a patch release to address CVE-2013-1620.

Detailed descriptions of the bugs fixed by nss-3.14.3 can be found in
the upstream release notes at
https://developer.mozilla.org/en-US/docs/NSS/NSS_3.14.3_release_notes

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=896651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=908257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=910584"
  );
  # https://developer.mozilla.org/en-US/docs/NSS/NSS_3.14.3_release_notes
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c94a8bf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-March/100068.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8bfd6f4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-March/100069.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?28b8acec"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-March/100070.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d87b17d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-March/100071.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57ea8a1a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nss-util");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:17");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^17([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 17.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC17", reference:"nspr-4.9.5-2.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"nss-3.14.3-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"nss-softokn-3.14.3-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"nss-util-3.14.3-1.fc17")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nss / nss-softokn / nss-util");
}
