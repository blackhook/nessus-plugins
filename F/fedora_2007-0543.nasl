#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-0543.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(27669);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2007-3099", "CVE-2007-3100");
  script_bugtraq_id(24471);
  script_xref(name:"FEDORA", value:"2007-0543");

  script_name(english:"Fedora 7 : iscsi-initiator-utils-6.2.0.865-0.0.fc7 (2007-0543)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to iscsi-initiator-utils is a rebase to the upstream
open-iscsi-2.0-865 release. This release include two security fixes,
bug fixes and new features.

The tools in this release use a different db format, but the tools are
able to read old and new formats. If you want to use the new features
you must update the db, by rediscovering your targets and
reconfiguring them (set per target CHAP, iscsi.node, iscsi.conn, etc
settings again). Once the db has been updated you cannot use older
tools on it.

See the README and man pages for information on the new features.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-June/002213.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?987d45bd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected iscsi-initiator-utils and / or
iscsi-initiator-utils-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:iscsi-initiator-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:iscsi-initiator-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"iscsi-initiator-utils-6.2.0.865-0.0.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"iscsi-initiator-utils-debuginfo-6.2.0.865-0.0.fc7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "iscsi-initiator-utils / iscsi-initiator-utils-debuginfo");
}
