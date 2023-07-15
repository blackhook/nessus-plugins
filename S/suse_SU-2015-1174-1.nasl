#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1174-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84545);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2014-8086", "CVE-2014-8159", "CVE-2014-9419", "CVE-2014-9529", "CVE-2014-9683", "CVE-2015-0777", "CVE-2015-1421", "CVE-2015-2041", "CVE-2015-2042", "CVE-2015-2150", "CVE-2015-2830", "CVE-2015-2922", "CVE-2015-3331", "CVE-2015-3339", "CVE-2015-3636");
  script_bugtraq_id(70376, 71794, 71880, 72356, 72643, 72729, 72730, 73014, 73060, 73699, 73921, 74235, 74243, 74315, 74450);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : kernel (SUSE-SU-2015:1174-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The SUSE Linux Enterprise 11 Service Pack 3 kernel was updated to fix
various bugs and security issues.

The following vulnerabilities have been fixed :

CVE-2015-3636: A missing sk_nulls_node_init() in ping_unhash() inside
the ipv4 stack can cause crashes if a disconnect is followed by
another connect() attempt. (bnc#929525)

CVE-2015-3339: Race condition in the prepare_binprm function in
fs/exec.c in the Linux kernel before 3.19.6 allows local users to gain
privileges by executing a setuid program at a time instant when a
chown to root is in progress, and the ownership is changed but the
setuid bit is not yet stripped. (bnc#928130)

CVE-2015-3331: The __driver_rfc4106_decrypt function in
arch/x86/crypto/aesni-intel_glue.c in the Linux kernel before 3.19.3
does not properly determine the memory locations used for encrypted
data, which allows context-dependent attackers to cause a denial of
service (buffer overflow and system crash) or possibly execute
arbitrary code by triggering a crypto API call, as demonstrated by use
of a libkcapi test program with an AF_ALG(aead) socket. (bnc#927257)

CVE-2015-2922: The ndisc_router_discovery function in net/ipv6/ndisc.c
in the Neighbor Discovery (ND) protocol implementation in the IPv6
stack in the Linux kernel before 3.19.6 allows remote attackers to
reconfigure a hop-limit setting via a small hop_limit value in a
Router Advertisement (RA) message. (bnc#922583)

CVE-2015-2830: arch/x86/kernel/entry_64.S in the Linux kernel before
3.19.2 does not prevent the TS_COMPAT flag from reaching a user-mode
task, which might allow local users to bypass the seccomp or audit
protection mechanism via a crafted application that uses the (1) fork
or (2) close system call, as demonstrated by an attack against seccomp
before 3.16. (bnc#926240)

CVE-2015-2150: XSA-120: Xen 3.3.x through 4.5.x and the Linux kernel
through 3.19.1 do not properly restrict access to PCI command
registers, which might allow local guest users to cause a denial of
service (non-maskable interrupt and host crash) by disabling the (1)
memory or (2) I/O decoding for a PCI Express device and then accessing
the device, which triggers an Unsupported Request (UR) response.
(bnc#919463)

CVE-2015-2042: net/rds/sysctl.c in the Linux kernel before 3.19 uses
an incorrect data type in a sysctl table, which allows local users to
obtain potentially sensitive information from kernel memory or
possibly have unspecified other impact by accessing a sysctl entry.
(bnc#919018)

CVE-2015-2041: net/llc/sysctl_net_llc.c in the Linux kernel before
3.19 uses an incorrect data type in a sysctl table, which allows local
users to obtain potentially sensitive information from kernel memory
or possibly have unspecified other impact by accessing a sysctl entry.
(bnc#919007)

CVE-2015-1421: Use-after-free vulnerability in the sctp_assoc_update
function in net/sctp/associola.c in the Linux kernel before 3.18.8
allows remote attackers to cause a denial of service (slab corruption
and panic) or possibly have unspecified other impact by triggering an
INIT collision that leads to improper handling of shared-key data.
(bnc#915577)

CVE-2015-0777: drivers/xen/usbback/usbback.c in 1 -2.6.18-xen-3.4.0
(aka the Xen 3.4.x support patches for the Linux kernel 2.6.18), as
used in the Linux kernel 2.6.x and 3.x in SUSE Linux distributions,
allows guest OS users to obtain sensitive information from
uninitialized locations in host OS kernel memory via unspecified
vectors. (bnc#917830)

CVE-2014-9683: Off-by-one error in the ecryptfs_decode_from_filename
function in fs/ecryptfs/crypto.c in the eCryptfs subsystem in the
Linux kernel before 3.18.2 allows local users to cause a denial of
service (buffer overflow and system crash) or possibly gain privileges
via a crafted filename. (bnc#918333)

CVE-2014-9529: Race condition in the key_gc_unused_keys function in
security/keys/gc.c in the Linux kernel through 3.18.2 allows local
users to cause a denial of service (memory corruption or panic) or
possibly have unspecified other impact via keyctl commands that
trigger access to a key structure member during garbage collection of
a key. (bnc#912202)

CVE-2014-9419: The __switch_to function in
arch/x86/kernel/process_64.c in the Linux kernel through 3.18.1 does
not ensure that Thread Local Storage (TLS) descriptors are loaded
before proceeding with other steps, which makes it easier for local
users to bypass the ASLR protection mechanism via a crafted
application that reads a TLS base address. (bnc#911326)

CVE-2014-8159: The InfiniBand (IB) implementation in the Linux kernel
does not properly restrict use of User Verbs for registration of
memory regions, which allows local users to access arbitrary physical
memory locations, and consequently cause a denial of service (system
crash) or gain privileges, by leveraging permissions on a uverbs
device under /dev/infiniband/. (bnc#914742)

CVE-2014-8086: Race condition in the ext4_file_write_iter function in
fs/ext4/file.c in the Linux kernel through 3.17 allows local users to
cause a denial of service (file unavailability) via a combination of a
write action and an F_SETFL fcntl operation for the O_DIRECT flag.
(bnc#900881)

Also 

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=831029"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=877456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=889221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=891212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=891641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=900881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=902286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=904242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=904883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=904901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=906027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=908706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=909309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=909312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=909477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=909684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=910517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=911326"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=912202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=912741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=913080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=913598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=914726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=914742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=914818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=914987"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=915045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=915200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=915577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=916521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=916848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=917093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=917120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=917648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=917684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=917830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=917839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=918333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=919007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=919018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=919357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=919463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=919589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=919682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=919808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=921769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=922583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=923344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=924142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=924271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=924333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=924340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=925012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=925370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=925443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=925567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=925729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=926016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=926240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=926439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=926767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=927190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=927257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=927262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=927338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=928122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=928130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=928142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=928333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=928970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=929145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=929148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=929283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=929525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=929647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=930145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=930171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=930226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=930284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=930401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=930669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=930786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=930788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=931014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=931015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=931850"
  );
  # https://download.suse.com/patch/finder/?keywords=03bfa6c75cb5a4cc6051fbc3690140d3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1c8e5da"
  );
  # https://download.suse.com/patch/finder/?keywords=33f906d57c7adfdab2c5c7c702cdcc35
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f0219dd"
  );
  # https://download.suse.com/patch/finder/?keywords=3e0de0ca574129367fbd700f1fcd6a34
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15a25b8b"
  );
  # https://download.suse.com/patch/finder/?keywords=613faa6f2a4360fe9998cf1191971acd
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58b62ba1"
  );
  # https://download.suse.com/patch/finder/?keywords=75c42977aa44422b8e12040ea373b902
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?631f6767"
  );
  # https://download.suse.com/patch/finder/?keywords=81a75ad520ef4ea9b9c573a7a188dc57
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58f65758"
  );
  # https://download.suse.com/patch/finder/?keywords=8c54aaa27bf9a5984cc9911a7413d962
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef02f47f"
  );
  # https://download.suse.com/patch/finder/?keywords=ad2768d3cc62a7649f30b1411b1594c7
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?84917562"
  );
  # https://download.suse.com/patch/finder/?keywords=ba8477a089d848b7d15e1cde80ddf9a0
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0db92481"
  );
  # https://download.suse.com/patch/finder/?keywords=eafe120fa23e6b5da6394f829b734878
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f112eac1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8086/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8159/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9419/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9529/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9683/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0777/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1421/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2041/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2042/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2150/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2830/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2922/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3331/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3339/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3636/"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151174-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a0a953a"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11 SP3 for VMware :

zypper in -t patch slessp3-kernel=10717 slessp3-kernel=10740

SUSE Linux Enterprise Server 11 SP3 :

zypper in -t patch slessp3-kernel=10717 slessp3-kernel=10718
slessp3-kernel=10719 slessp3-kernel=10720 slessp3-kernel=10740

SUSE Linux Enterprise High Availability Extension 11 SP3 :

zypper in -t patch slehasp3-kernel=10717 slehasp3-kernel=10718
slehasp3-kernel=10719 slehasp3-kernel=10720 slehasp3-kernel=10740

SUSE Linux Enterprise Desktop 11 SP3 :

zypper in -t patch sledsp3-kernel=10717 sledsp3-kernel=10740

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp-devel");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES11" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-kmp-default-4.2.5_08_3.0.101_0.47.55-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-kmp-pae-4.2.5_08_3.0.101_0.47.55-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"kernel-default-man-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-source-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-syms-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-kmp-default-4.2.5_08_3.0.101_0.47.55-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-kmp-pae-4.2.5_08_3.0.101_0.47.55-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-extra-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-source-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-syms-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-trace-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-extra-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-kmp-default-4.2.5_08_3.0.101_0.47.55-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-extra-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-kmp-pae-4.2.5_08_3.0.101_0.47.55-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-extra-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-source-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-syms-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-trace-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-extra-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"xen-kmp-default-4.2.5_08_3.0.101_0.47.55-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-extra-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"xen-kmp-pae-4.2.5_08_3.0.101_0.47.55-0.7.1")) flag++;


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
