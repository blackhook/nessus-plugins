#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119219);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2017-10978",
    "CVE-2017-10979",
    "CVE-2017-10980",
    "CVE-2017-10981",
    "CVE-2017-10982",
    "CVE-2017-10983"
  );

  script_name(english:"Virtuozzo 6 : freeradius / freeradius-krb5 / freeradius-ldap / etc (VZLSA-2017-1759)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for freeradius is now available for Red Hat Enterprise Linux
6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

FreeRADIUS is a high-performance and highly configurable free Remote
Authentication Dial In User Service (RADIUS) server, designed to allow
centralized authentication and authorization for a network.

Security Fix(es) :

* An out-of-bounds write flaw was found in the way FreeRADIUS server
handled certain attributes in request packets. A remote attacker could
use this flaw to crash the FreeRADIUS server or to execute arbitrary
code in the context of the FreeRADIUS server process by sending a
specially crafted request packet. (CVE-2017-10979)

* An out-of-bounds read and write flaw was found in the way FreeRADIUS
server handled RADIUS packets. A remote attacker could use this flaw
to crash the FreeRADIUS server by sending a specially crafted RADIUS
packet. (CVE-2017-10978)

* Multiple memory leak flaws were found in the way FreeRADIUS server
handled decoding of DHCP packets. A remote attacker could use these
flaws to cause the FreeRADIUS server to consume an increasing amount
of memory resources over time, possibly leading to a crash due to
memory exhaustion, by sending specially crafted DHCP packets.
(CVE-2017-10980, CVE-2017-10981)

* Multiple out-of-bounds read flaws were found in the way FreeRADIUS
server handled decoding of DHCP packets. A remote attacker could use
these flaws to crash the FreeRADIUS server by sending a specially
crafted DHCP request. (CVE-2017-10982, CVE-2017-10983)

Red Hat would like to thank the FreeRADIUS project for reporting these
issues. Upstream acknowledges Guido Vranken as the original reporter
of these issues.

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2017-1759.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d6cef56");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:1759");
  script_set_attribute(attribute:"solution", value:
"Update the affected freeradius / freeradius-krb5 / freeradius-ldap / etc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:freeradius-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:freeradius-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:freeradius-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:freeradius-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:freeradius-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:freeradius-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:freeradius-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:freeradius-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = pregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 6.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["freeradius-2.2.6-7.vl6",
        "freeradius-krb5-2.2.6-7.vl6",
        "freeradius-ldap-2.2.6-7.vl6",
        "freeradius-mysql-2.2.6-7.vl6",
        "freeradius-perl-2.2.6-7.vl6",
        "freeradius-postgresql-2.2.6-7.vl6",
        "freeradius-python-2.2.6-7.vl6",
        "freeradius-unixODBC-2.2.6-7.vl6",
        "freeradius-utils-2.2.6-7.vl6"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-6", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeradius / freeradius-krb5 / freeradius-ldap / etc");
}
