#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-c894f896fd.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120784);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"FEDORA", value:"2018-c894f896fd");

  script_name(english:"Fedora 28 : knot-resolver (2018-c894f896fd)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Knot Resolver 2.4.0 (2018-07-03) ================================

Incompatible changes

--------------------

  - minimal libknot version is now 2.6.7 to pull in latest
    fixes (#366)

Security

--------

  - fix a rare case of zones incorrectly dowgraded to
    insecure status (!576)

New features

------------

  - TLS session resumption (RFC 5077), both server and
    client (!585, #105) (disabled when compiling with gnutls
    < 3.5)

  - TLS_FORWARD policy uses system CA certificate store by
    default (!568)

  - aggressive caching for NSEC3 zones (!600)

  - optional protection from DNS Rebinding attack (module
    rebinding, !608)

  - module bogus_log to log DNSSEC bogus queries without
    verbose logging (!613)

Bugfixes

--------

  - prefill: fix ability to read certificate bundle (!578)

  - avoid turning off qname minimization in some cases, e.g.
    co.uk. (#339)

  - fix validation of explicit wildcard queries (#274)

  - dns64 module: more properties from the RFC implemented
    (incl. bug #375)

Improvements

------------

  - systemd: multiple enabled kresd instances can now be
    started using kresd.target

  - ta_sentinel: switch to version 14 of the RFC draft
    (!596)

  - support for glibc systems with a non-Linux kernel (!588)

  - support per-request variables for Lua modules (!533)

  - support custom HTTP endpoints for Lua modules (!527)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-c894f896fd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected knot-resolver package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:knot-resolver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:28");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^28([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 28", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC28", reference:"knot-resolver-2.4.0-1.fc28")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "knot-resolver");
}
