#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:1135-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99758);
  script_version("3.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2016-10155", "CVE-2016-9776", "CVE-2016-9907", "CVE-2016-9911", "CVE-2016-9921", "CVE-2016-9922", "CVE-2017-2615", "CVE-2017-2620", "CVE-2017-5856", "CVE-2017-5898");
  script_xref(name:"IAVB", value:"2017-B-0024-S");

  script_name(english:"SUSE SLES11 Security Update : kvm (SUSE-SU-2017:1135-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for kvm fixes several issues. These security issues were
fixed :

  - CVE-2017-2620: In CIRRUS_BLTMODE_MEMSYSSRC mode the
    bitblit copy routine cirrus_bitblt_cputovideo failed to
    check the memory region, allowing for an out-of-bounds
    write that allows for privilege escalation (bsc#1024972)

  - CVE-2017-2615: An error in the bitblt copy operation
    could have allowed a malicious guest administrator to
    cause an out of bounds memory access, possibly leading
    to information disclosure or privilege escalation
    (bsc#1023004)

  - CVE-2016-9776: The ColdFire Fast Ethernet Controller
    emulator support was vulnerable to an infinite loop
    issue while receiving packets in 'mcf_fec_receive'. A
    privileged user/process inside guest could have used
    this issue to crash the Qemu process on the host leading
    to DoS (bsc#1013285)

  - CVE-2016-9911: The USB EHCI Emulation support was
    vulnerable to a memory leakage issue while processing
    packet data in 'ehci_init_transfer'. A guest
    user/process could have used this issue to leak host
    memory, resulting in DoS for the host (bsc#1014111)

  - CVE-2016-9907: The USB redirector usb-guest support was
    vulnerable to a memory leakage flaw when destroying the
    USB redirector in 'usbredir_handle_destroy'. A guest
    user/process could have used this issue to leak host
    memory, resulting in DoS for a host (bsc#1014109)

  - CVE-2016-9921: The Cirrus CLGD 54xx VGA Emulator support
    was vulnerable to a divide by zero issue while copying
    VGA data. A privileged user inside guest could have used
    this flaw to crash the process instance on the host,
    resulting in DoS (bsc#1014702)

  - CVE-2016-9922: The Cirrus CLGD 54xx VGA Emulator support
    was vulnerable to a divide by zero issue while copying
    VGA data. A privileged user inside guest could have used
    this flaw to crash the process instance on the host,
    resulting in DoS (bsc#1014702)

  - CVE-2017-5898: The CCID Card device emulator support was
    vulnerable to an integer overflow allowing a privileged
    user inside the guest to crash the Qemu process
    resulting in DoS (bnc#1023907)

  - CVE-2016-10155: The virtual hardware watchdog
    'wdt_i6300esb' was vulnerable to a memory leakage issue
    allowing a privileged user to cause a DoS and/or
    potentially crash the Qemu process on the host
    (bsc#1021129)

  - CVE-2017-5856: The MegaRAID SAS 8708EM2 Host Bus Adapter
    emulation support was vulnerable to a memory leakage
    issue allowing a privileged user to leak host memory
    resulting in DoS (bsc#1023053)

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1013285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1014109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1014111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1014702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1015048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1015169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1016779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1021129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1023004"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1023053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1023907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1024972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10155/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9776/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9907/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9911/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9921/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9922/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2615/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2620/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5856/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5898/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20171135-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7e97675"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-kvm-13080=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kvm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"kvm-1.4.2-59.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kvm");
}
