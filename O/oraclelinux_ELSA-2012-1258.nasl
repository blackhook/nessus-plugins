#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:1258 and 
# Oracle Linux Security Advisory ELSA-2012-1258 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68617);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-1674", "CVE-2011-3323", "CVE-2011-3324", "CVE-2011-3325", "CVE-2011-3326", "CVE-2011-3327", "CVE-2012-0249", "CVE-2012-0250");
  script_bugtraq_id(25634, 42635, 46942, 49784, 52531);
  script_xref(name:"RHSA", value:"2012:1258");

  script_name(english:"Oracle Linux 5 : quagga (ELSA-2012-1258)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:1258 :

Updated quagga packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Quagga is a TCP/IP based routing software suite. The Quagga bgpd
daemon implements the BGP (Border Gateway Protocol) routing protocol.
The Quagga ospfd and ospf6d daemons implement the OSPF (Open Shortest
Path First) routing protocol.

A heap-based buffer overflow flaw was found in the way the bgpd daemon
processed malformed Extended Communities path attributes. An attacker
could send a specially crafted BGP message, causing bgpd on a target
system to crash or, possibly, execute arbitrary code with the
privileges of the user running bgpd. The UPDATE message would have to
arrive from an explicitly configured BGP peer, but could have
originated elsewhere in the BGP network. (CVE-2011-3327)

A NULL pointer dereference flaw was found in the way the bgpd daemon
processed malformed route Extended Communities attributes. A
configured BGP peer could crash bgpd on a target system via a
specially crafted BGP message. (CVE-2010-1674)

A stack-based buffer overflow flaw was found in the way the ospf6d
daemon processed malformed Link State Update packets. An OSPF router
could use this flaw to crash ospf6d on an adjacent router.
(CVE-2011-3323)

A flaw was found in the way the ospf6d daemon processed malformed link
state advertisements. An OSPF neighbor could use this flaw to crash
ospf6d on a target system. (CVE-2011-3324)

A flaw was found in the way the ospfd daemon processed malformed Hello
packets. An OSPF neighbor could use this flaw to crash ospfd on a
target system. (CVE-2011-3325)

A flaw was found in the way the ospfd daemon processed malformed link
state advertisements. An OSPF router in the autonomous system could
use this flaw to crash ospfd on a target system. (CVE-2011-3326)

An assertion failure was found in the way the ospfd daemon processed
certain Link State Update packets. An OSPF router could use this flaw
to cause ospfd on an adjacent router to abort. (CVE-2012-0249)

A buffer overflow flaw was found in the way the ospfd daemon processed
certain Link State Update packets. An OSPF router could use this flaw
to crash ospfd on an adjacent router. (CVE-2012-0250)

Red Hat would like to thank CERT-FI for reporting CVE-2011-3327,
CVE-2011-3323, CVE-2011-3324, CVE-2011-3325, and CVE-2011-3326; and
the CERT/CC for reporting CVE-2012-0249 and CVE-2012-0250. CERT-FI
acknowledges Riku Hietamaki, Tuomo Untinen and Jukka Taimisto of the
Codenomicon CROSS project as the original reporters of CVE-2011-3327,
CVE-2011-3323, CVE-2011-3324, CVE-2011-3325, and CVE-2011-3326. The
CERT/CC acknowledges Martin Winter at OpenSourceRouting.org as the
original reporter of CVE-2012-0249 and CVE-2012-0250.

Users of quagga should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the bgpd, ospfd, and ospf6d daemons will be
restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-September/003022.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected quagga packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:quagga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:quagga-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:quagga-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"quagga-0.98.6-7.el5_8.1")) flag++;
if (rpm_check(release:"EL5", reference:"quagga-contrib-0.98.6-7.el5_8.1")) flag++;
if (rpm_check(release:"EL5", reference:"quagga-devel-0.98.6-7.el5_8.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "quagga / quagga-contrib / quagga-devel");
}
