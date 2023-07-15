#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-b7d774a7c1.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120732);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2018-10920");
  script_xref(name:"FEDORA", value:"2018-b7d774a7c1");

  script_name(english:"Fedora 28 : knot-resolver (2018-b7d774a7c1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Knot Resolver 2.4.1 (2018-08-02) ================================

Security

--------

  - fix CVE-2018-10920: Improper input validation bug in DNS
    resolver component (security!7, security!9)

Bugfixes

--------

  - cache: fix TTL overflow in packet due to min_ttl (#388,
    security!8)

  - TLS session resumption: avoid bad scheduling of rotation
    (#385)

  - HTTP module: fix a regression in 2.4.0 which broke
    custom certs (!632)

  - cache: NSEC3 negative cache even without NS record
    (#384) This fixes lower hit rate in NSEC3 zones (since
    2.4.0).

  - minor TCP and TLS fixes (!623, !624, !626)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-b7d774a7c1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected knot-resolver package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:knot-resolver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:28");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
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
if (rpm_check(release:"FC28", reference:"knot-resolver-2.4.1-1.fc28")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "knot-resolver");
}
