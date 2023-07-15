#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0455-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(106866);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2017-16227",
    "CVE-2017-5495",
    "CVE-2018-5378",
    "CVE-2018-5379",
    "CVE-2018-5380",
    "CVE-2018-5381"
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0227");

  script_name(english:"SUSE SLES12 Security Update : quagga (SUSE-SU-2018:0455-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for quagga fixes the following security issues :

  - The Quagga BGP daemon contained a bug in the AS_PATH
    size calculation that could have been exploited to
    facilitate a remote denial-of-service attack via
    specially crafted BGP UPDATE messages. [CVE-2017-16227,
    bsc#1065641]

  - The Quagga BGP daemon did not check whether data sent to
    peers via NOTIFY had an invalid attribute length. It was
    possible to exploit this issue and cause the bgpd
    process to leak sensitive information over the network
    to a configured peer. [CVE-2018-5378, bsc#1079798]

  - The Quagga BGP daemon used to double-free memory when
    processing certain forms of UPDATE messages. This issue
    could be exploited by sending an optional/transitive
    UPDATE attribute that all conforming eBGP speakers
    should pass along. Consequently, a single UPDATE message
    could have affected many bgpd processes across a wide
    area of a network. Through this vulnerability, attackers
    could potentially have taken over control of affected
    bgpd processes remotely. [CVE-2018-5379, bsc#1079799]

  - It was possible to overrun internal BGP code-to-string
    conversion tables in the Quagga BGP daemon. Configured
    peers could have exploited this issue and cause bgpd to
    emit debug and warning messages into the logs that would
    contained arbitrary bytes. [CVE-2018-5380, bsc#1079800]

  - The Quagga BGP daemon could have entered an infinite
    loop if sent an invalid OPEN message by a configured
    peer. If this issue was exploited, then bgpd would cease
    to respond to any other events. BGP sessions would have
    been dropped and not be reestablished. The CLI interface
    would have been unresponsive. The bgpd daemon would have
    stayed in this state until restarted. [CVE-2018-5381,
    bsc#1079801]

  - The Quagga daemon's telnet 'vty' CLI contains an
    unbounded memory allocation bug that could be exploited
    for a denial-of-service attack on the daemon. This issue
    has been fixed. [CVE-2017-5495, bsc#1021669]

  - The telnet 'vty' CLI of the Quagga daemon is no longer
    enabled by default, because the passwords in the default
    'zebra.conf' config file are now disabled. The vty
    interface is available via 'vtysh' utility using pam
    authentication to permit management access for root
    without password. [bsc#1021669]

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1021669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1065641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1079798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1079799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1079800");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1079801");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-16227/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-5495/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-5378/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-5379/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-5380/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-5381/");
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180455-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad61f40b");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 6:zypper in -t patch
SUSE-OpenStack-Cloud-6-2018-315=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2018-315=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2018-315=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2018-315=1

To bring your system up-to-date, use 'zypper patch'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:quagga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:quagga-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:quagga-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES12" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"quagga-0.99.22.1-16.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"quagga-debuginfo-0.99.22.1-16.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"quagga-debugsource-0.99.22.1-16.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"quagga-0.99.22.1-16.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"quagga-debuginfo-0.99.22.1-16.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"quagga-debugsource-0.99.22.1-16.4.1")) flag++;


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
