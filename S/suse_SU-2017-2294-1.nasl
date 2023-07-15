#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2294-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102841);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2016-1245", "CVE-2017-5495");

  script_name(english:"SUSE SLES12 Security Update : quagga (SUSE-SU-2017:2294-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update provides Quagga 1.1.1, which brings several fixes and
enhancements. Security issues fixed :

  - CVE-2017-5495: Telnet 'vty' interface DoS due to
    unbounded memory allocation. (bsc#1021669)

  - CVE-2016-1245: Stack overrun in IPv6 RA receive code.
    (bsc#1005258) Bug fixes :

  - Do not enable zebra's TCP interface (port 2600) to use
    default UNIX socket for communication between the
    daemons. (fate#323170) Between 0.99.22.1 and 1.1.1 the
    following improvements have been implemented :

  - Changed the default of 'link-detect' state, controlling
    whether zebra will respond to link-state events and
    consider an interface to be down when link is down. To
    retain the current behavior save your config before
    updating, otherwise remove the 'link-detect' flag from
    your config prior to updating. There is also a new
    global 'default link-detect (on|off)' flag to configure
    the global default.

  - Greatly improved nexthop resolution for recursive
    routes.

  - Event driven nexthop resolution for BGP.

  - Route tags support.

  - Transport of TE related metrics over OSPF, IS-IS.

  - IPv6 Multipath for zebra and BGP.

  - Multicast RIB support has been extended. It still is
    IPv4 only.

  - RIP for IPv4 now supports equal-cost multipath (ECMP).

  - route-maps have a new action 'set ipv6 next-hop
    peer-address'.

  - route-maps have a new action 'set as-path prepend
    last-as'.

  - 'next-hop-self all' to override nexthop on iBGP route
    reflector setups.

  - New pimd daemon provides IPv4 PIM-SSM multicast routing.

  - IPv6 address management has been improved regarding
    tentative addresses. This is visible in that a freshly
    configured address will not immediately be marked as
    usable.

  - Recursive route support has been overhauled. Scripts
    parsing 'show ip route' output may need adaptation.

  - A large amount of changes has been merged for ospf6d.
    Careful evaluation prior to deployment is recommended.

  - Multiprotocol peerings over IPv6 now try to find a more
    appropriate IPv4 nexthop by looking at the interface.

  - Relaxed bestpath criteria for multipath and improved
    display of multipath routes in 'show ip bgp'. Scripts
    parsing this output may need to be updated.

  - Support for iBGP TTL security.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1005258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1021669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1034273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1245/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5495/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172294-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61003eb7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2017-1407=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-1407=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-1407=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2017-1407=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-1407=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfpm_pb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfpm_pb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libospf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libospf0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libospfapiclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libospfapiclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libquagga_pb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libquagga_pb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzebra1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzebra1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:quagga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:quagga-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:quagga-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"libfpm_pb0-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libfpm_pb0-debuginfo-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libospf0-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libospf0-debuginfo-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libospfapiclient0-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libospfapiclient0-debuginfo-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libquagga_pb0-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libquagga_pb0-debuginfo-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libzebra1-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libzebra1-debuginfo-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"quagga-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"quagga-debuginfo-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"quagga-debugsource-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libfpm_pb0-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libfpm_pb0-debuginfo-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libospf0-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libospf0-debuginfo-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libospfapiclient0-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libospfapiclient0-debuginfo-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libquagga_pb0-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libquagga_pb0-debuginfo-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libzebra1-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libzebra1-debuginfo-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"quagga-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"quagga-debuginfo-1.1.1-17.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"quagga-debugsource-1.1.1-17.3.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "quagga");
}
