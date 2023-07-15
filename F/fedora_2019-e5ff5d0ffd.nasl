#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-e5ff5d0ffd.
#

include("compat.inc");

if (description)
{
  script_id(129857);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/19");

  script_cve_id("CVE-2019-5829", "CVE-2019-5831", "CVE-2019-5832", "CVE-2019-5837", "CVE-2019-5839", "CVE-2019-5842", "CVE-2019-5851", "CVE-2019-5852", "CVE-2019-5854", "CVE-2019-5855", "CVE-2019-5856", "CVE-2019-5857", "CVE-2019-5860", "CVE-2019-5861", "CVE-2019-5862", "CVE-2019-5865");
  script_xref(name:"FEDORA", value:"2019-e5ff5d0ffd");

  script_name(english:"Fedora 29 : qt5-qtwebengine (2019-e5ff5d0ffd)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A bugfix and security update of QtWebEngine to 5.12.5, the latest
release from the 5.12 LTS branch.

Security fixes from Chromium up to version 76.0.3809.87, including :

  - CVE-2019-5829

  - CVE-2019-5831

  - CVE-2019-5832

  - CVE-2019-5837

  - CVE-2019-5839

  - CVE-2019-5842

  - CVE-2019-5851

  - CVE-2019-5852

  - CVE-2019-5854

  - CVE-2019-5855

  - CVE-2019-5856

  - CVE-2019-5857

  - CVE-2019-5860

  - CVE-2019-5861

  - CVE-2019-5862

  - CVE-2019-5865

  - Critical security issue 977057

  - Security bug 934161

  - Security bug 939644

  - Security bug 948172

  - Security bug 948228

  - Security bug 948944

  - Security bug 950005

  - Security bug 952849

  - Security bug 956625

  - Security bug 958457

  - Security bug 958689

  - Security bug 959193

  - Security bug 959518

  - Security bug 958717

  - Security bug 960785

  - Security bug 961674

  - Security bug 961597

  - Security bug 962083

  - Security bug 964002

  - Security bug 973893

  - Security bug 974627

  - Security bug 976050

  - Security bug 981602

  - Security bug 983850

  - Security bug 983938

General bug fixes :

  - [QTBUG-62106] Fixed possible crash after rapid tapping.

  - [QTBUG-75884] Fixed crash on setHttpUserAgent.

  - [QTBUG-76249] Fixed user-agent on some new windows.

  - [QTBUG-76268] Fixed tab key send on minimize.

  - [QTBUG-76347] Fixed duplicate events being send from
    tablets.

  - [QTBUG-76828] Clear shared context on exit.

  - [QTBUG-76958] Fixed possible crash when loading in
    background.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-e5ff5d0ffd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qt5-qtwebengine package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtwebengine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:29");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^29([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 29", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC29", reference:"qt5-qtwebengine-5.12.5-2.fc29")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qt5-qtwebengine");
}
