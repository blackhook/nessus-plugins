#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-0199.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(29848);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2008-0095");
  script_bugtraq_id(27110);
  script_xref(name:"FEDORA", value:"2008-0199");

  script_name(english:"Fedora 8 : asterisk-1.4.17-1.fc8 (2008-0199)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fixes AST-2008-001. See :

http://downloads.digium.com/pub/security/AST-2008-001.html

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://downloads.digium.com/pub/security/AST-2008-001.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://downloads.digium.com/pub/security/AST-2008-001.html"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-January/006520.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e16e9ca9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk-conference");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk-fax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk-festival");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk-jabber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk-misdn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk-mobile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk-oss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk-radius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk-skinny");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk-tds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk-voicemail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk-voicemail-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk-voicemail-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk-voicemail-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk-zaptel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/04");
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
if (rpm_check(release:"FC8", reference:"asterisk-1.4.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"asterisk-alsa-1.4.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"asterisk-conference-1.4.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"asterisk-curl-1.4.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"asterisk-debuginfo-1.4.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"asterisk-devel-1.4.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"asterisk-fax-1.4.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"asterisk-festival-1.4.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"asterisk-firmware-1.4.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"asterisk-jabber-1.4.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"asterisk-misdn-1.4.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"asterisk-mobile-1.4.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"asterisk-odbc-1.4.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"asterisk-oss-1.4.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"asterisk-postgresql-1.4.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"asterisk-radius-1.4.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"asterisk-skinny-1.4.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"asterisk-snmp-1.4.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"asterisk-tds-1.4.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"asterisk-voicemail-1.4.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"asterisk-voicemail-imap-1.4.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"asterisk-voicemail-odbc-1.4.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"asterisk-voicemail-plain-1.4.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"asterisk-zaptel-1.4.17-1.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "asterisk / asterisk-alsa / asterisk-conference / asterisk-curl / etc");
}
