#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0481-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(88834);
  script_version("2.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2015-8605");

  script_name(english:"SUSE SLED11 / SLES11 Security Update : dhcp (SUSE-SU-2016:0481-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for dhcp fixes the following issues :

  - CVE-2015-8605: A remote attacker could have used badly
    formed packets with an invalid IPv4 UDP length field to
    cause a DHCP server, client, or relay program to
    terminate abnormally (bsc#961305)

The following bugs were fixed :

  - bsc#936923: Improper lease duration checking

  - bsc#880984: Integer overflows in the date and time
    handling code

  - bsc#947780: DHCP server could abort with 'Unable to set
    up timer: out of range' on very long or infinite timer
    intervals / lease lifetimes

  - bsc#926159: DHCP preferrend and valid lifetime would be
    logged incorrectly

  - bsc#928390: dhclient dit not expose next-server DHCPv4
    option to script

  - bsc#926159: DHCP preferrend and valid lifetime would be
    logged incorrectly

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=880984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=919959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=926159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=928390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=936923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=947780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=961305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8605/"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160481-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?042a8b0d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-dhcp-12410=1

SUSE Linux Enterprise Software Development Kit 11-SP3 :

zypper in -t patch sdksp3-dhcp-12410=1

SUSE Linux Enterprise Server for VMWare 11-SP3 :

zypper in -t patch slessp3-dhcp-12410=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-dhcp-12410=1

SUSE Linux Enterprise Server 11-SP3 :

zypper in -t patch slessp3-dhcp-12410=1

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-dhcp-12410=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-dhcp-12410=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-dhcp-12410=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-dhcp-12410=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dhcp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dhcp-relay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dhcp-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED11|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"dhcp-4.2.4.P2-0.24.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"dhcp-client-4.2.4.P2-0.24.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"dhcp-relay-4.2.4.P2-0.24.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"dhcp-server-4.2.4.P2-0.24.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"dhcp-4.2.4.P2-0.24.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"dhcp-client-4.2.4.P2-0.24.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"dhcp-relay-4.2.4.P2-0.24.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"dhcp-server-4.2.4.P2-0.24.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"dhcp-4.2.4.P2-0.24.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"dhcp-client-4.2.4.P2-0.24.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"dhcp-4.2.4.P2-0.24.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"dhcp-client-4.2.4.P2-0.24.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"dhcp-4.2.4.P2-0.24.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"dhcp-client-4.2.4.P2-0.24.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"dhcp-4.2.4.P2-0.24.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"dhcp-client-4.2.4.P2-0.24.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhcp");
}
