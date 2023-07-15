#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0794 and 
# CentOS Errata and Security Advisory 2017:0794 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(97961);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-2236", "CVE-2016-1245", "CVE-2016-2342", "CVE-2016-4049", "CVE-2017-5495");
  script_xref(name:"RHSA", value:"2017:0794");

  script_name(english:"CentOS 6 : quagga (CESA-2017:0794)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for quagga is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The quagga packages contain Quagga, the free network-routing software
suite that manages TCP/IP based protocols. Quagga supports the BGP4,
BGP4+, OSPFv2, OSPFv3, RIPv1, RIPv2, and RIPng protocols, and is
intended to be used as a Route Server and Route Reflector.

Security Fix(es) :

* A stack-based buffer overflow flaw was found in the way Quagga
handled IPv6 router advertisement messages. A remote attacker could
use this flaw to crash the zebra daemon resulting in denial of
service. (CVE-2016-1245)

* A stack-based buffer overflow flaw was found in the way the Quagga
BGP routing daemon (bgpd) handled Labeled-VPN SAFI routes data. A
remote attacker could use this flaw to crash the bgpd daemon resulting
in denial of service. (CVE-2016-2342)

* A denial of service flaw was found in the Quagga BGP routing daemon
(bgpd). Under certain circumstances, a remote attacker could send a
crafted packet to crash the bgpd daemon resulting in denial of
service. (CVE-2016-4049)

* A denial of service flaw affecting various daemons in Quagga was
found. A remote attacker could use this flaw to cause the various
Quagga daemons, which expose their telnet interface, to crash.
(CVE-2017-5495)

* A stack-based buffer overflow flaw was found in the way the Quagga
OSPFD daemon handled LSA (link-state advertisement) packets. A remote
attacker could use this flaw to crash the ospfd daemon resulting in
denial of service. (CVE-2013-2236)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.9 Release Notes and Red Hat Enterprise Linux 6.9
Technical Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-March/003917.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06a1a5d3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected quagga packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5495");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:quagga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:quagga-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:quagga-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"quagga-0.99.15-14.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"quagga-contrib-0.99.15-14.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"quagga-devel-0.99.15-14.el6")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "quagga / quagga-contrib / quagga-devel");
}
