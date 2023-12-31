#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-16022.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(62647);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2012-5166");
  script_bugtraq_id(55852);
  script_xref(name:"FEDORA", value:"2012-16022");

  script_name(english:"Fedora 18 : bind-dyndb-ldap-2.0-0.3.20121009git6a86b1.fc18 / bind-9.9.2-2.fc18 / etc (2012-16022)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to the latest BIND packages to fix CVE-2012-5166 and
incorporate other fixes from upstream. Packages dhcp, bind-dyndb-ldap
and dnsperf were rebuilt.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=864273"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-October/090489.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?95bf508d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-October/090490.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d2dd5629"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-October/090491.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f77e3c31"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-October/090492.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b050bb9b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bind-dyndb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dnsperf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/22");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"bind-9.9.2-2.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"bind-dyndb-ldap-2.0-0.3.20121009git6a86b1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"dhcp-4.2.4-18.P2.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"dnsperf-2.0.0.0-3.fc18")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-dyndb-ldap / dhcp / dnsperf");
}
