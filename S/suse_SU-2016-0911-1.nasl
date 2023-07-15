#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0911-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90264);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2013-7446", "CVE-2015-7515", "CVE-2015-7550", "CVE-2015-8539", "CVE-2015-8543", "CVE-2015-8550", "CVE-2015-8551", "CVE-2015-8552", "CVE-2015-8569", "CVE-2015-8575", "CVE-2015-8767", "CVE-2015-8785", "CVE-2015-8812", "CVE-2016-0723", "CVE-2016-2069", "CVE-2016-2384", "CVE-2016-2543", "CVE-2016-2544", "CVE-2016-2545", "CVE-2016-2546", "CVE-2016-2547", "CVE-2016-2548", "CVE-2016-2549");

  script_name(english:"SUSE SLED11 / SLES11 Security Update : kernel (SUSE-SU-2016:0911-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various
security and bugfixes.

Following feature was added to kernel-xen :

  - A improved XEN blkfront module was added, which allows
    more I/O bandwidth. (FATE#320200) It is called
    xen-blkfront in PV, and xen-vbd-upstream in HVM mode.

The following security bugs were fixed :

  - CVE-2013-7446: Use-after-free vulnerability in
    net/unix/af_unix.c in the Linux kernel allowed local
    users to bypass intended AF_UNIX socket permissions or
    cause a denial of service (panic) via crafted epoll_ctl
    calls (bnc#955654).

  - CVE-2015-7515: An out of bounds memory access in the
    aiptek USB driver could be used by physical local
    attackers to crash the kernel (bnc#956708).

  - CVE-2015-7550: The keyctl_read_key function in
    security/keys/keyctl.c in the Linux kernel did not
    properly use a semaphore, which allowed local users to
    cause a denial of service (NULL pointer dereference and
    system crash) or possibly have unspecified other impact
    via a crafted application that leverages a race
    condition between keyctl_revoke and keyctl_read calls
    (bnc#958951).

  - CVE-2015-8539: The KEYS subsystem in the Linux kernel
    allowed local users to gain privileges or cause a denial
    of service (BUG) via crafted keyctl commands that
    negatively instantiate a key, related to
    security/keys/encrypted-keys/encrypted.c,
    security/keys/trusted.c, and
    security/keys/user_defined.c (bnc#958463).

  - CVE-2015-8543: The networking implementation in the
    Linux kernel did not validate protocol identifiers for
    certain protocol families, which allowed local users to
    cause a denial of service (NULL function pointer
    dereference and system crash) or possibly gain
    privileges by leveraging CLONE_NEWUSER support to
    execute a crafted SOCK_RAW application (bnc#958886).

  - CVE-2015-8550: Compiler optimizations in the XEN PV
    backend drivers could have lead to double fetch
    vulnerabilities, causing denial of service or arbitrary
    code execution (depending on the configuration)
    (bsc#957988).

  - CVE-2015-8551, CVE-2015-8552: xen/pciback: For
    XEN_PCI_OP_disable_msi[|x] only disable if device has
    MSI(X) enabled (bsc#957990).

  - CVE-2015-8569: The (1) pptp_bind and (2) pptp_connect
    functions in drivers/net/ppp/pptp.c in the Linux kernel
    did not verify an address length, which allowed local
    users to obtain sensitive information from kernel memory
    and bypass the KASLR protection mechanism via a crafted
    application (bnc#959190).

  - CVE-2015-8575: The sco_sock_bind function in
    net/bluetooth/sco.c in the Linux kernel did not verify
    an address length, which allowed local users to obtain
    sensitive information from kernel memory and bypass the
    KASLR protection mechanism via a crafted application
    (bnc#959190 bnc#959399).

  - CVE-2015-8767: net/sctp/sm_sideeffect.c in the Linux
    kernel did not properly manage the relationship between
    a lock and a socket, which allowed local users to cause
    a denial of service (deadlock) via a crafted sctp_accept
    call (bnc#961509).

  - CVE-2015-8785: The fuse_fill_write_pages function in
    fs/fuse/file.c in the Linux kernel allowed local users
    to cause a denial of service (infinite loop) via a
    writev system call that triggers a zero length for the
    first segment of an iov (bnc#963765).

  - CVE-2015-8812: A use-after-free flaw was found in the
    CXGB3 kernel driver when the network was considered to
    be congested. This could be used by local attackers to
    cause machine crashes or potentially code execution
    (bsc#966437).

  - CVE-2016-0723: Race condition in the tty_ioctl function
    in drivers/tty/tty_io.c in the Linux kernel allowed
    local users to obtain sensitive information from kernel
    memory or cause a denial of service (use-after-free and
    system crash) by making a TIOCGETD ioctl call during
    processing of a TIOCSETD ioctl call (bnc#961500).

  - CVE-2016-2069: Race conditions in TLB syncing was fixed
    which could leak to information leaks (bnc#963767).

  - CVE-2016-2384: Removed a double free in the ALSA
    usb-audio driver in the umidi object which could lead to
    crashes (bsc#966693).

  - CVE-2016-2543: Added a missing NULL check at
    remove_events ioctl in ALSA that could lead to crashes.
    (bsc#967972).

  - CVE-2016-2544, CVE-2016-2545, CVE-2016-2546,
    CVE-2016-2547, CVE-2016-2548, CVE-2016-2549: Various
    race conditions in ALSAs timer handling were fixed.
    (bsc#967975, bsc#967974, bsc#967973, bsc#968011,
    bsc#968012, bsc#968013).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=758040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=904035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=912738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=915183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=924919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=933782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=937444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=940017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=940946"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=942082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=947128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=948330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=949298"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=951392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=951815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=952976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=953369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=954992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=955308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=955654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=955837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=955925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=957986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=957988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=957990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=958000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=958463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=958886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=958906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=958912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=958951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=959190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=959312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=959399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=959649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=959705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=961500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=961509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=961516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=961658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=962965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=963276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=963561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=963765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=963767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=964201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=964818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=966094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=966137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=966437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=966693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=967042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=967972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=967973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=967974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=967975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=968011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=968012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=968013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=969307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-7446/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7515/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7550/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8539/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8543/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8550/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8551/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8552/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8569/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8575/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8767/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8785/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8812/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0723/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2069/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2384/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2543/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2544/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2545/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2546/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2547/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2548/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2549/"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160911-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97a0fcf5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-kernel-201603-12480=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-kernel-201603-12480=1

SUSE Linux Enterprise Server 11-EXTRA :

zypper in -t patch slexsp3-kernel-201603-12480=1

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-kernel-201603-12480=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-kernel-201603-12480=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");
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
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"kernel-default-man-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-source-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-syms-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-default-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-default-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-default-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-default-extra-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-source-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-syms-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-trace-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-xen-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-xen-extra-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-pae-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-pae-extra-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-default-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-default-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-default-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-default-extra-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-source-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-syms-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-trace-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-xen-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-xen-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-xen-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-xen-extra-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-pae-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-pae-base-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-pae-devel-3.0.101-71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-pae-extra-3.0.101-71.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
