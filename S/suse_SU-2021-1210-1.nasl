#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:1210-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(148700);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2020-0433",
    "CVE-2020-25670",
    "CVE-2020-25671",
    "CVE-2020-25672",
    "CVE-2020-25673",
    "CVE-2020-27170",
    "CVE-2020-27171",
    "CVE-2020-27815",
    "CVE-2020-29368",
    "CVE-2020-29374",
    "CVE-2020-35519",
    "CVE-2020-36311",
    "CVE-2021-3428",
    "CVE-2021-3444",
    "CVE-2021-3483",
    "CVE-2021-20219",
    "CVE-2021-26930",
    "CVE-2021-26931",
    "CVE-2021-26932",
    "CVE-2021-27363",
    "CVE-2021-27364",
    "CVE-2021-27365",
    "CVE-2021-28038",
    "CVE-2021-28660",
    "CVE-2021-28688",
    "CVE-2021-28964",
    "CVE-2021-28971",
    "CVE-2021-28972",
    "CVE-2021-29154",
    "CVE-2021-29264",
    "CVE-2021-29265",
    "CVE-2021-29647",
    "CVE-2021-30002"
  );

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2021:1210-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various
security and bugfixes.

The following security bugs were fixed :

CVE-2021-3444: Fixed an issue with the bpf verifier which did not
properly handle mod32 destination register truncation when the source
register was known to be 0 leading to out of bounds read
(bsc#1184170).

CVE-2021-3428: Fixed an integer overflow in ext4_es_cache_extent
(bsc#1173485).

CVE-2021-29647: Fixed an issue in qrtr_recvmsg which could have
allowed attackers to obtain sensitive information from kernel memory
because of a partially uninitialized data structure (bsc#1184192 ).

CVE-2021-29265: Fixed an issue in usbip_sockfd_store which could have
allowed attackers to cause a denial of service due to race conditions
during an update of the local and shared status (bsc#1184167).

CVE-2021-29264: Fixed an issue in the Freescale Gianfar Ethernet
driver which could have allowed attackers to cause a system crash due
to a calculation of negative fragment size (bsc#1184168).

CVE-2021-28972: Fixed a user-tolerable buffer overflow when writing a
new device name to the driver from userspace, allowing userspace to
write data to the kernel stack frame directly (bsc#1184198).

CVE-2021-28971: Fixed an issue in intel_pmu_drain_pebs_nhm which could
have caused a system crash because the PEBS status in a PEBS record
was mishandled (bsc#1184196 ).

CVE-2021-28964: Fixed a race condition in get_old_root which could
have allowed attackers to cause a denial of service (bsc#1184193).

CVE-2021-28688: Fixed an issue introduced by XSA-365 (bsc#1183646).

CVE-2021-28660: Fixed an out of bounds write in rtw_wx_set_scan
(bsc#1183593 ).

CVE-2021-28038: Fixed an issue with the netback driver which was
lacking necessary treatment of errors such as failed memory
allocations (bsc#1183022).

CVE-2021-27365: Fixed an issue where an unprivileged user can send a
Netlink message that is associated with iSCSI, and has a length up to
the maximum length of a Netlink message (bsc#1182715).

CVE-2021-27364: Fixed an issue where an attacker could craft Netlink
messages (bsc#1182717).

CVE-2021-27363: Fixed a kernel pointer leak which could have been used
to determine the address of the iscsi_transport structure
(bsc#1182716).

CVE-2021-26932: Fixed improper error handling issues in Linux grant
mapping (XSA-361 bsc#1181747).

CVE-2021-26931: Fixed an issue where Linux kernel was treating grant
mapping errors as bugs (XSA-362 bsc#1181753).

CVE-2021-26930: Fixed an improper error handling in blkback's grant
mapping (XSA-365 bsc#1181843).

CVE-2020-35519: Fixed an out-of-bounds memory access was found in
x25_bind (bsc#1183696).

CVE-2020-29368,CVE-2020-29374: Fixed an issue in copy-on-write
implementation which could have granted unintended write access
(bsc#1179660, bsc#1179428).

CVE-2020-27815: Fixed an issue in JFS filesystem where could have
allowed an attacker to execute code (bsc#1179454).

CVE-2020-27171: Fixed an off-by-one error affecting out-of-bounds
speculation on pointer arithmetic, leading to side-channel attacks
that defeat Spectre mitigations and obtain sensitive information from
kernel memory (bsc#1183775).

CVE-2020-27170: Fixed potential side-channel attacks that defeat
Spectre mitigations and obtain sensitive information from kernel
memory (bsc#1183686).

CVE-2020-0433: Fixed a use after free due to improper locking which
could have led to local escalation of privilege (bsc#1176720).

CVE-2021-3483: Fixed a use-after-free in nosy.c (bsc#1184393).

CVE-2021-30002: Fixed a memory leak for large arguments in
video_usercopy (bsc#1184120).

CVE-2021-29154: Fixed incorrect computation of branch displacements,
allowing arbitrary code execution (bsc#1184391).

CVE-2021-20219: Fixed a denial of service in
n_tty_receive_char_special (bsc#1184397).

CVE-2020-36311: Fixed a denial of service (soft lockup) by triggering
destruction of a large SEV VM (bsc#1184511).

CVE-2020-25670, CVE-2020-25671, CVE-2020-25672, CVE-2020-25673: Fixed
multiple bugs in NFC subsytem (bsc#1178181).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1065600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1103990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1103991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1103992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1104270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1104353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1109837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1111981");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1112374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1113295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1113994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1118657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1118661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1119113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1126390");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1129770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1132477");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1142635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1152446");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1154048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1169709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1175165");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178163");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178181");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181515");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181544");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181674");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181753");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1182011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1182175");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1182485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1182574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1182715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1182716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1182717");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183023");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183380");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183382");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184196");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184393");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184397");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184583");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-0433/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25670/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25671/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25672/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25673/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27170/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27171/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27815/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29368/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29374/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35519/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36311/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20219/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-26930/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-26931/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-26932/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-27363/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-27364/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-27365/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28038/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28660/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28688/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28964/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28971/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28972/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29154/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29264/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29265/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29647/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30002/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3428/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3444/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3483/");
  # https://www.suse.com/support/update/announcement/2021/suse-su-20211210-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?07418a12");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP5 :

zypper in -t patch SUSE-SLE-WE-12-SP5-2021-1210=1

SUSE Linux Enterprise Software Development Kit 12-SP5 :

zypper in -t patch SUSE-SLE-SDK-12-SP5-2021-1210=1

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2021-1210=1

SUSE Linux Enterprise Live Patching 12-SP5 :

zypper in -t patch SUSE-SLE-Live-Patching-12-SP5-2021-1210=1

SUSE Linux Enterprise High Availability 12-SP5 :

zypper in -t patch SUSE-SLE-HA-12-SP5-2021-1210=1");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28660");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"5", cpu:"x86_64", reference:"kernel-default-devel-debuginfo-4.12.14-122.66.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"s390x", reference:"kernel-default-man-4.12.14-122.66.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"kernel-default-4.12.14-122.66.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"kernel-default-base-4.12.14-122.66.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"kernel-default-base-debuginfo-4.12.14-122.66.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"kernel-default-debuginfo-4.12.14-122.66.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"kernel-default-debugsource-4.12.14-122.66.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"kernel-default-devel-4.12.14-122.66.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"kernel-syms-4.12.14-122.66.2")) flag++;


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
