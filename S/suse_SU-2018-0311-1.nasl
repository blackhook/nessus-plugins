#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0311-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(106555);
  script_version("3.5");
  script_cvs_date("Date: 2019/09/10 13:51:46");

  script_cve_id("CVE-2017-14970", "CVE-2017-9214", "CVE-2017-9263", "CVE-2017-9265");

  script_name(english:"SUSE SLES12 Security Update : openvswitch (SUSE-SU-2018:0311-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openvswitch fixes the following issues :

  - CVE-2017-9263: While parsing an OpenFlow role status
    message, there is a call to the abort() functio for
    undefined role status reasons in the function
    `ofp_print_role_status_message` in `lib/ofp-print.c`
    that may be leveraged toward a remote DoS attack by a
    malicious switch. (bsc#1041470)

  - CVE-2017-9265: Buffer over-read while parsing the group
    mod OpenFlow message sent from the controller in
    `lib/ofp-util.c` in the function
    `ofputil_pull_ofp15_group_mod`.(bsc#1041447)

  - CVE-2017-9214: While parsing an
    OFPT_QUEUE_GET_CONFIG_REPLY type OFP 1.0 message, there
    is a buffer over-read that is caused by an unsigned
    integer underflow in the function
    `ofputil_pull_queue_get_config_reply10` in
    `lib/ofp-util.c`. (bsc#1040543)

  - CVE-2017-14970: In lib/ofp-util.c, there are multiple
    memory leaks while parsing malformed OpenFlow group mod
    messages.(bsc#1061310)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1040543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1041447"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1041470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14970/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9214/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9263/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9265/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180311-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8ef9ad8b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2018-229=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-229=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch-dpdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch-dpdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch-dpdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch-dpdk-switch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch-dpdk-switch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch-switch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch-switch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"openvswitch-dpdk-2.5.1-25.12.8")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"openvswitch-dpdk-debuginfo-2.5.1-25.12.8")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"openvswitch-dpdk-debugsource-2.5.1-25.12.8")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"openvswitch-dpdk-switch-2.5.1-25.12.8")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"openvswitch-dpdk-switch-debuginfo-2.5.1-25.12.8")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openvswitch-2.5.1-25.12.7")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openvswitch-debuginfo-2.5.1-25.12.7")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openvswitch-debugsource-2.5.1-25.12.7")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openvswitch-switch-2.5.1-25.12.7")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openvswitch-switch-debuginfo-2.5.1-25.12.7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openvswitch");
}
