#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2004-219.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(13738);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2004-0633", "CVE-2004-0634", "CVE-2004-0635");
  script_xref(name:"FEDORA", value:"2004-219");

  script_name(english:"Fedora Core 1 : ethereal-0.10.5-0.1.1 (2004-219)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Issues have been discovered in the following protocol dissectors :

  - The iSNS dissector could make Ethereal abort in some
    cases. (0.10.3 - 0.10.4) CVE-2004-0633

  - SMB SID snooping could crash if there was no policy name
    for a handle. (0.9.15 - 0.10.4) CVE-2004-0634

  - The SNMP dissector could crash due to a malformed or
    missing community string. (0.8.15 - 0.10.4)
    CVE-2004-0635

Impact :

It may be possible to make Ethereal crash or run arbitrary code by
injecting a purposefully malformed packet onto the wire or by
convincing someone to read a malformed packet trace file.

Resolution :

Upgrade to 0.10.5.

If you are running a version prior to 0.10.5 and you cannot upgrade,
you can disable all of the protocol dissectors listed above by
selecting Analyze->Enabled Protocols... and deselecting them from the
list. For SMB, you can alternatively disable SID snooping in the SMB
protocol preferences. However, it is strongly recommended that you
upgrade to 0.10.5.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2004-July/000215.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ceffb6b1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected ethereal, ethereal-debuginfo and / or
ethereal-gnome packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ethereal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ethereal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ethereal-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 1.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC1", reference:"ethereal-0.10.5-0.1.1")) flag++;
if (rpm_check(release:"FC1", reference:"ethereal-debuginfo-0.10.5-0.1.1")) flag++;
if (rpm_check(release:"FC1", reference:"ethereal-gnome-0.10.5-0.1.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ethereal / ethereal-debuginfo / ethereal-gnome");
}
