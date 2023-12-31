#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-9161.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84174);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2015-4000");
  script_xref(name:"FEDORA", value:"2015-9161");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Fedora 20 : nss-3.19.1-1.0.fc20 / nss-softokn-3.19.1-1.0.fc20 / nss-util-3.19.1-1.0.fc20 (2015-9161) (Logjam)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Security fix for CVE-2015-4000

Update to the upstream NSS 3.19.1 release, which includes a fix for
the recently published logjam attack.

The previous 3.19 release made several notable changes related to the
TLS protocol, one of them was to disable the SSL 3 protocol by
default.

For the full list of changes in the 3.19 and 3.19.1 releases, please
refer to the upstream release notes documents :

https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.19
.1_release_notes

https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.19
_release_notes

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1223211");
  # https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.19.1_release_notes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d8e3334");
  # https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.19_release_notes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22a37d19");
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-June/160116.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea81ea47");
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-June/160117.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce88be86");
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-June/160118.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b5444cc");
  script_set_attribute(attribute:"solution", value:
"Update the affected nss, nss-softokn and / or nss-util packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nss-util");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2022 Tenable Network Security, Inc.");

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
if (rpm_check(release:"FC20", reference:"nss-3.19.1-1.0.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"nss-softokn-3.19.1-1.0.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"nss-util-3.19.1-1.0.fc20")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-softokn / nss-util");
}
