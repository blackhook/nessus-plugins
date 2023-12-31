#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-0642.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(53901);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2011-0015", "CVE-2011-0016", "CVE-2011-0427", "CVE-2011-0490", "CVE-2011-0491", "CVE-2011-0492", "CVE-2011-0493");
  script_bugtraq_id(45832, 45953);
  script_xref(name:"FEDORA", value:"2011-0642");

  script_name(english:"Fedora 14 : tor-0.2.1.29-1400.fc14 (2011-0642)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Mon Jan 17 2011 Enrico Scholz <enrico.scholz at
    informatik.tu-chemnitz.de> - 0.2.1.29-1400

    - updated to 0.2.1.29 (SECURITY)

    - CVE-2011-0427: heap overflow bug, potential remote
      code execution

    - Tue Dec 21 2010 Luke Macken <lmacken at redhat.com> -
      0.2.1.28-1400

    - updated to 0.2.1.28 (SECURITY: fixes a remotely
      exploitable heap overflow bug)

    - Fri Nov 26 2010 Enrico Scholz <enrico.scholz at
      informatik.tu-chemnitz.de> - 0.2.1.27-1400

    - updated to 0.2.1.27

    - work around broken chkconfig by adding dummy
      Default-Start: in -lsb (#647512)

    - Fri Nov 26 2010 Enrico Scholz <enrico.scholz at
      informatik.tu-chemnitz.de> - 0.2.1.26-1401

    - fixed 'limit' statement in upstart script

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=671259"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-May/060123.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9ba2cee8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tor package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"tor-0.2.1.29-1400.fc14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tor");
}
