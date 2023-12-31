#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-4259.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58549);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2011-4597", "CVE-2011-4598", "CVE-2012-1183", "CVE-2012-1184");
  script_bugtraq_id(50989, 50990, 52523, 52815);
  script_xref(name:"FEDORA", value:"2012-4259");

  script_name(english:"Fedora 15 : asterisk-1.8.10.1-1.fc15 (2012-4259)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to 1.8.10.1, which fixes 2 security vulnerabilities. The
Asterisk Development Team has announced security releases for Asterisk
1.4, 1.6.2 and 1.8. The available security releases are released as
versions 1.4.43, 1.6.2.21 and 1.8.7.2.

These releases are available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk/releases

The release of Asterisk versions 1.4.43, 1.6.2.21, and 1.8.7.2
resolves an issue with possible remote enumeration of SIP endpoints
with differing NAT settings.

The release of Asterisk versions 1.6.2.21 and 1.8.7.2 resolves a
remote crash possibility with SIP when the 'automon' feature is
enabled.

The issues and resolutions are described in the AST-2011-013 and
AST-2011-014 security advisories.

For more information about the details of these vulnerabilities,
please read the security advisories AST-2011-013 and AST-2011-014,
which were released at the same time as this announcement.

For a full list of changes in the current releases, please see the
ChangeLogs :

http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.4.43
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.6.2.21
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.8.7.2

Security advisory AST-2011-013 is available at :

  -
    http://downloads.asterisk.org/pub/security/AST-2011-013.
    pdf

Security advisory AST-2011-014 is available at :

  -
    http://downloads.asterisk.org/pub/security/AST-2011-014.
    pdf

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2011-013.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2011-014.pdf"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/releases/"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.4.43
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d3e0301"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.6.2.21
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de7eb2c6"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.8.7.2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c680dc0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=765773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=765776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=804038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=804042"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-March/076654.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5fa7bf9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected asterisk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^15([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 15.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC15", reference:"asterisk-1.8.10.1-1.fc15")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "asterisk");
}
