#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:1841-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150191);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-25217");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : dhcp (SUSE-SU-2021:1841-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for dhcp fixes the following issues :

CVE-2021-25217: A buffer overrun in lease file parsing code can be
used to exploit a common vulnerability shared by dhcpd and dhclient
(bsc#1186382)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1186382");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25217/");
  # https://www.suse.com/support/update/announcement/2021/suse-su-20211841-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ae4925d");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Manager Server 4.0 :

zypper in -t patch
SUSE-SLE-Product-SUSE-Manager-Server-4.0-2021-1841=1

SUSE Manager Retail Branch Server 4.0 :

zypper in -t patch
SUSE-SLE-Product-SUSE-Manager-Retail-Branch-Server-4.0-2021-1841=1

SUSE Manager Proxy 4.0 :

zypper in -t patch SUSE-SLE-Product-SUSE-Manager-Proxy-4.0-2021-1841=1

SUSE Linux Enterprise Server for SAP 15-SP1 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-SP1-2021-1841=1

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2021-1841=1

SUSE Linux Enterprise Server 15-SP1-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-SP1-LTSS-2021-1841=1

SUSE Linux Enterprise Server 15-SP1-BCL :

zypper in -t patch SUSE-SLE-Product-SLES-15-SP1-BCL-2021-1841=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2021-1841=1

SUSE Linux Enterprise Module for Server Applications 15-SP3 :

zypper in -t patch
SUSE-SLE-Module-Server-Applications-15-SP3-2021-1841=1

SUSE Linux Enterprise Module for Server Applications 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Server-Applications-15-SP2-2021-1841=1

SUSE Linux Enterprise Module for Basesystem 15-SP3 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP3-2021-1841=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2021-1841=1

SUSE Linux Enterprise High Performance Computing 15-SP1-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-SP1-LTSS-2021-1841=1

SUSE Linux Enterprise High Performance Computing 15-SP1-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-SP1-ESPOS-2021-1841=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2021-1841=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2021-1841=1

SUSE Enterprise Storage 6 :

zypper in -t patch SUSE-Storage-6-2021-1841=1

SUSE CaaS Platform 4.0 :

To install this update, use the SUSE CaaS Platform 'skuba' tool. I
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25217");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dhcp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dhcp-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dhcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dhcp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dhcp-relay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dhcp-relay-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dhcp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dhcp-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1|2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1/2/3", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"dhcp-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dhcp-client-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dhcp-client-debuginfo-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dhcp-debuginfo-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dhcp-debugsource-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dhcp-devel-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dhcp-relay-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dhcp-relay-debuginfo-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dhcp-server-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dhcp-server-debuginfo-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"dhcp-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"dhcp-client-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"dhcp-client-debuginfo-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"dhcp-debuginfo-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"dhcp-debugsource-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"dhcp-devel-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"dhcp-relay-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"dhcp-relay-debuginfo-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"dhcp-server-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"dhcp-server-debuginfo-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"dhcp-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"dhcp-client-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"dhcp-client-debuginfo-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"dhcp-debuginfo-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"dhcp-debugsource-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"dhcp-devel-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"dhcp-relay-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"dhcp-relay-debuginfo-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"dhcp-server-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"dhcp-server-debuginfo-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"dhcp-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"dhcp-client-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"dhcp-client-debuginfo-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"dhcp-debuginfo-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"dhcp-debugsource-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"dhcp-devel-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"dhcp-relay-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"dhcp-relay-debuginfo-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"dhcp-server-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"dhcp-server-debuginfo-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"dhcp-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"dhcp-client-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"dhcp-client-debuginfo-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"dhcp-debuginfo-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"dhcp-debugsource-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"dhcp-devel-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"dhcp-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"dhcp-client-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"dhcp-client-debuginfo-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"dhcp-debuginfo-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"dhcp-debugsource-4.3.6.P1-6.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"dhcp-devel-4.3.6.P1-6.11.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhcp");
}
