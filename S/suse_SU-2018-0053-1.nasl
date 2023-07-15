#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0053-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(106092);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2014-3710", "CVE-2014-8116", "CVE-2014-8117", "CVE-2014-9620", "CVE-2014-9621", "CVE-2014-9653", "CVE-2014-9939", "CVE-2017-12448", "CVE-2017-12450", "CVE-2017-12452", "CVE-2017-12453", "CVE-2017-12454", "CVE-2017-12456", "CVE-2017-12799", "CVE-2017-12837", "CVE-2017-12883", "CVE-2017-13757", "CVE-2017-14128", "CVE-2017-14129", "CVE-2017-14130", "CVE-2017-14333", "CVE-2017-14529", "CVE-2017-14729", "CVE-2017-14745", "CVE-2017-14974", "CVE-2017-3735", "CVE-2017-3736", "CVE-2017-3737", "CVE-2017-3738", "CVE-2017-6512", "CVE-2017-6965", "CVE-2017-6966", "CVE-2017-6969", "CVE-2017-7209", "CVE-2017-7210", "CVE-2017-7223", "CVE-2017-7224", "CVE-2017-7225", "CVE-2017-7226", "CVE-2017-7299", "CVE-2017-7300", "CVE-2017-7301", "CVE-2017-7302", "CVE-2017-7303", "CVE-2017-7304", "CVE-2017-8392", "CVE-2017-8393", "CVE-2017-8394", "CVE-2017-8396", "CVE-2017-8421", "CVE-2017-9746", "CVE-2017-9747", "CVE-2017-9748", "CVE-2017-9750", "CVE-2017-9755", "CVE-2017-9756");
  script_bugtraq_id(70807, 71692, 71700, 71714, 71715, 72516);

  script_name(english:"SUSE SLES12 Security Update : CaaS Platform 2.0 images (SUSE-SU-2018:0053-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Docker images provided with SUSE CaaS Platform 2.0 have been
updated to include the following updates: binutils :

  - Update to version 2.29

  - 18750 bsc#1030296 CVE-2014-9939

  - 20891 bsc#1030585 CVE-2017-7225

  - 20892 bsc#1030588 CVE-2017-7224

  - 20898 bsc#1030589 CVE-2017-7223

  - 20905 bsc#1030584 CVE-2017-7226

  - 20908 bsc#1031644 CVE-2017-7299

  - 20909 bsc#1031656 CVE-2017-7300

  - 20921 bsc#1031595 CVE-2017-7302

  - 20922 bsc#1031593 CVE-2017-7303

  - 20924 bsc#1031638 CVE-2017-7301

  - 20931 bsc#1031590 CVE-2017-7304

  - 21135 bsc#1030298 CVE-2017-7209

  - 21137 bsc#1029909 CVE-2017-6965

  - 21139 bsc#1029908 CVE-2017-6966

  - 21156 bsc#1029907 CVE-2017-6969

  - 21157 bsc#1030297 CVE-2017-7210

  - 21409 bsc#1037052 CVE-2017-8392

  - 21412 bsc#1037057 CVE-2017-8393

  - 21414 bsc#1037061 CVE-2017-8394

  - 21432 bsc#1037066 CVE-2017-8396

  - 21440 bsc#1037273 CVE-2017-8421

  - 21580 bsc#1044891 CVE-2017-9746

  - 21581 bsc#1044897 CVE-2017-9747

  - 21582 bsc#1044901 CVE-2017-9748

  - 21587 bsc#1044909 CVE-2017-9750

  - 21594 bsc#1044925 CVE-2017-9755

  - 21595 bsc#1044927 CVE-2017-9756

  - 21787 bsc#1052518 CVE-2017-12448

  - 21813 bsc#1052503, CVE-2017-12456, bsc#1052507,
    CVE-2017-12454, bsc#1052509, CVE-2017-12453,
    bsc#1052511, CVE-2017-12452, bsc#1052514,
    CVE-2017-12450, bsc#1052503, CVE-2017-12456,
    bsc#1052507, CVE-2017-12454, bsc#1052509,
    CVE-2017-12453, bsc#1052511, CVE-2017-12452,
    bsc#1052514, CVE-2017-12450

  - 21933 bsc#1053347 CVE-2017-12799

  - 21990 bsc#1058480 CVE-2017-14333

  - 22018 bsc#1056312 CVE-2017-13757

  - 22047 bsc#1057144 CVE-2017-14129

  - 22058 bsc#1057149 CVE-2017-14130

  - 22059 bsc#1057139 CVE-2017-14128

  - 22113 bsc#1059050 CVE-2017-14529

  - 22148 bsc#1060599 CVE-2017-14745

  - 22163 bsc#1061241 CVE-2017-14974

  - 22170 bsc#1060621 CVE-2017-14729

  - Make compressed debug section handling explicit, disable
    for old products and enable for gas on all architectures
    otherwise. [bsc#1029995]

  - Remove empty rpath component removal optimization from
    to workaround CMake rpath handling. [bsc#1025282]

  - Fix alignment frags for aarch64 (bsc#1003846) 
coreutils :

  - Fix df(1) to no longer interact with excluded file
    system types, so for example specifying -x nfs no longer
    hangs with problematic nfs mounts. (bsc#1026567)

  - Ensure df -l no longer interacts with dummy file system
    types, so for example no longer hangs with problematic
    NFS mounted via system.automount(5). (bsc#1043059)

  - Significantly speed up df(1) for huge mount lists.
    (bsc#965780) file :

  - update to version 5.22.

  - CVE-2014-9621: The ELF parser in file allowed remote
    attackers to cause a denial of service via a long
    string. (bsc#913650)

  - CVE-2014-9620: The ELF parser in file allowed remote
    attackers to cause a denial of service via a large
    number of notes. (bsc#913651)

  - CVE-2014-9653: readelf.c in file did not consider that
    pread calls sometimes read only a subset of the
    available data, which allows remote attackers to cause a
    denial of service (uninitialized memory access) or
    possibly have unspecified other impact via a crafted ELF
    file. (bsc#917152)

  - CVE-2014-8116: The ELF parser (readelf.c) in file
    allowed remote attackers to cause a denial of service
    (CPU consumption or crash) via a large number of (1)
    program or (2) section headers or (3) invalid
    capabilities. (bsc#910253)

  - CVE-2014-8117: softmagic.c in file did not properly
    limit recursion, which allowed remote attackers to cause
    a denial of service (CPU consumption or crash) via
    unspecified vectors. (bsc#910253)

  - Fixed a memory corruption during rpmbuild (bsc#1063269)

  - Backport of a fix for an increased printable string
    length as found in file 5.30 (bsc#996511)

  - file command throws 'Composite Document File V2
    Document, corrupt: Can't read SSAT' error against excel
    97/2003 file format. (bsc#1009966) gcc7 :

  - Support for specific IBM Power9 processor instructions.

  - Support for specific IBM zSeries z14 processor
    instructions.

  - New packages cross-npvtx-gcc7 and nvptx-tools added to
    the Toolchain Module for specific NVIDIA Card offload
    support. gzip :

  - fix mishandling of leading zeros in the end-of-block
    code (bsc#1067891) libsolv :

  - Many fixes and improvements for cleandeps.

  - Always create dup rules for 'distupgrade' jobs.

  - Use recommends also for ordering packages.

  - Fix splitprovides handling with addalreadyrecommended
    turned off. (bsc#1059065)

  - Expose solver_get_recommendations() in bindings.

  - Fix bug in solver_prune_to_highest_prio_per_name
    resulting in bad output from
    solver_get_recommendations().

  - Support 'without' and 'unless' dependencies.

  - Use same heuristic as upstream to determine source RPMs.

  - Fix memory leak in bindings.

  - Add pool_best_solvables() function.

  - Fix 64bit integer parsing from RPM headers.

  - Enable bzip2 and xz/lzma compression support.

  - Enable complex/rich dependencies on distributions with
    RPM 4.13+. libtool :

  - Add missing dependencies and provides to baselibs.conf
    to make sure libltdl libraries are properly installed.
    (bsc#1056381) libzypp :

  - Fix media handling in presence of a repo path prefix.
    (bsc#1062561)

  - Fix RepoProvideFile ignoring a repo path prefix.
    (bsc#1062561)

  - Remove unused legacy notify-message script.
    (bsc#1058783)

  - Support multiple product licenses in repomd.
    (fate#322276)

  - Propagate 'rpm --import' errors. (bsc#1057188)

  - Fix typos in zypp.conf. openssl :

  - CVE-2017-3735: openssl1,openssl: Malformed X.509
    IPAdressFamily could cause OOB read (bsc#1056058)

  - CVE-2017-3736: openssl: bn_sqrx8x_internal carry bug on
    x86_64 (bsc#1066242)

  - Out of bounds read+crash in DES_fcrypt (bsc#1065363)

  - openssl DEFAULT_SUSE cipher list is missing ECDHE-ECDSA
    ciphers (bsc#1055825) perl: Security issues for perl :

  - CVE-2017-12837: Heap-based buffer overflow in the
    S_regatom function in regcomp.c in Perl 5 before
    5.24.3-RC1 and 5.26.x before 5.26.1-RC1 allows remote
    attackers to cause a denial of service (out-of-bounds
    write) via a regular expression with a escape and the
    case-insensitive modifier. (bnc#1057724)

  - CVE-2017-12883: Buffer overflow in the S_grok_bslash_N
    function in regcomp.c in Perl 5 before 5.24.3-RC1 and
    5.26.x before 5.26.1-RC1 allows remote attackers to
    disclose sensitive information or cause a denial of
    service (application crash) via a crafted regular
    expression with an invalid escape. (bnc#1057721)

  - CVE-2017-6512: Race condition in the rmtree and
    remove_tree functions in the File-Path module before
    2.13 for Perl allows attackers to set the mode on
    arbitrary files via vectors involving
    directory-permission loosening logic. (bnc#1047178) Bug
    fixes for perl :

  - backport set_capture_string changes from upstream
    (bsc#999735)

  - reformat baselibs.conf as source validator workaround
    systemd :

  - unit: When JobTimeoutSec= is turned off, implicitly turn
    off JobRunningTimeoutSec= too. (bsc#1048605,
    bsc#1004995)

  - compat-rules: Generate compat by-id symlinks with 'nvme'
    prefix missing and warn users that have broken symlinks.
    (bsc#1063249)

  - compat-rules: Allow to specify the generation number
    through the kernel command line.

  - scsi_id: Fixup prefix for pre-SPC inquiry reply.
    (bsc#1039099)

  - tmpfiles: Remove old ICE and X11 sockets at boot.

  - tmpfiles: Silently ignore any path that passes through
    autofs. (bsc#1045472)

  - pam_logind: Skip leading /dev/ from PAM_TTY field before
    passing it on.

  - shared/machine-pool: Fix another mkfs.btrfs checking.
    (bsc#1053595)

  - shutdown: Fix incorrect fscanf() result check.

  - shutdown: Don't remount,ro network filesystems.
    (bsc#1035386)

  - shutdown: Don't be fooled when detaching DM devices with
    BTRFS. (bsc#1055641)

  - bash-completion: Add support for --now. (bsc#1053137)

  - Add convert-lib-udev-path.sh script to convert /lib/udev
    directory into a symlink pointing to /usr/lib/udev when
    upgrading from SLE11. (bsc#1050152)

  - Add a rule to teach hotplug to offline containers
    transparently. (bsc#1040800) timezone :

  - Northern Cyprus switches from +03 to +02/+03 on
    2017-10-29

  - Fiji ends DST 2018-01-14, not 2018-01-21

  - Namibia switches from +01/+02 to +02 on 2018-04-01

  - Sudan switches from +03 to +02 on 2017-11-01

  - Tonga likely switches from +13/+14 to +13 on 2017-11-05

  - Turks and Caicos switches from -04 to -05/-04 on
    2018-11-04

  - Corrections to past DST transitions

  - Move oversized Canada/East-Saskatchewan to 'backward'
    file

  - zic(8) and the reference runtime now reject multiple
    leap seconds within 28 days of each other, or leap
    seconds before the Epoch. util-linux :

  - Allow unmounting of filesystems without calling stat()
    on the mount point, when '-c' is used. (bsc#1040968)

  - Fix an infinite loop, a crash and report the correct
    minimum and maximum frequencies in lscpu for some
    processors. (bsc#1055446)

  - Fix a lscpu failure on Sydney Amazon EC2 region.
    (bsc#1066500)

  - If multiple subvolumes are mounted, report the default
    subvolume. (bsc#1039276) velum :

  - Fix logout issue on DEX download page * page doesn't
    exist (bsc#1066611)

  - Handle invalid sessions more user friendly

  - Fix undesired minimum nodes alert blink (bsc#1066371)
    wicked :

  - A regression in wicked was causing the hostname not to
    be set correctly via DHCP in some cases
    (bsc#1057007,bsc#1050258)

  - Configure the interface MTU correctly even in cases
    where the interface was up already (bsc#1059292)

  - Don't abort the process that adds configures routes if
    one route fails (bsc#1036619)

  - Handle DHCP4 user-class ids properly (bsc#1045522)

  - ethtool: handle channels parameters (bsc#1043883) 
zypper :

  - Locale: Fix possible segmentation fault. (bsc#1064999)

  - Add summary hint if product is better updated by a
    different command. This is mainly used by rolling
    distributions like openSUSE Tumbleweed to remind their
    users to use 'zypper dup' to update (not zypper up or
    patch). (bsc#1061384)

  - Unify '(add|modify)(repo|service)' property related
    arguments.

  - Fixed 'add' commands supporting to set only a subset of
    properties.

  - Introduced '-f/-F' as preferred short option for
    --[no-]refresh in all four commands. (bsc#661410,
    bsc#1053671)

  - Fix missing package names in installation report.
    (bsc#1058695)

  - Differ between unsupported and packages with unknown
    support status. (bsc#1057634)

  - Return error code '107' if an RPM's %post configuration
    script fails, but only if ZYPPER_ON_CODE12_RETURN_107=1
    is set in the environment. (bsc#1047233)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1003846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1004995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1009966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1022404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1025282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1025891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1026567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1029907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1029908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1029909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1029995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1030623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1035386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1036619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1039099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1039276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1039513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1040800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1040968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1041090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1043059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1043590"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1043883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1043966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1044016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1047178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1047233"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1048605"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1048861"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1053137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1053347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1053595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1053671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1055446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1055641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1055825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057139"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057149"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1058480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1058695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1058783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1059050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1059065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1059075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1059292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1059723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1060599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1060621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1062561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1063249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1063269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1065363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1067891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1070878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1070958"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1071905"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1071906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3710/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8116/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8117/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9620/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9621/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9653/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12448/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12450/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12452/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12453/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12454/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12456/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12799/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12837/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12883/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13757/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14128/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14129/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14130/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14333/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14529/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14729/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14745/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14974/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3735/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3736/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3737/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3738/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6512/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180053-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2e30c71"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE CaaS Platform ALL:zypper in -t patch SUSE-CAASP-ALL-2018-40=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sles12-caasp-dex-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sles12-dnsmasq-nanny-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sles12-haproxy-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sles12-kubedns-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sles12-mariadb-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sles12-openldap-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sles12-pause-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sles12-pv-recycler-node-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sles12-salt-api-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sles12-salt-master-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sles12-salt-minion-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sles12-sidecar-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sles12-tiller-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sles12-velum-image");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);



flag = 0;
if (rpm_check(release:"SLES12", cpu:"x86_64", reference:"sles12-caasp-dex-image-2.0.0-3.3.11")) flag++;
if (rpm_check(release:"SLES12", cpu:"x86_64", reference:"sles12-dnsmasq-nanny-image-2.0.1-2.3.15")) flag++;
if (rpm_check(release:"SLES12", cpu:"x86_64", reference:"sles12-haproxy-image-2.0.1-2.3.16")) flag++;
if (rpm_check(release:"SLES12", cpu:"x86_64", reference:"sles12-kubedns-image-2.0.1-2.3.11")) flag++;
if (rpm_check(release:"SLES12", cpu:"x86_64", reference:"sles12-mariadb-image-2.0.1-2.3.15")) flag++;
if (rpm_check(release:"SLES12", cpu:"x86_64", reference:"sles12-openldap-image-2.0.0-2.3.11")) flag++;
if (rpm_check(release:"SLES12", cpu:"x86_64", reference:"sles12-pause-image-2.0.1-2.3.9")) flag++;
if (rpm_check(release:"SLES12", cpu:"x86_64", reference:"sles12-pv-recycler-node-image-2.0.1-2.3.10")) flag++;
if (rpm_check(release:"SLES12", cpu:"x86_64", reference:"sles12-salt-api-image-2.0.1-2.3.10")) flag++;
if (rpm_check(release:"SLES12", cpu:"x86_64", reference:"sles12-salt-master-image-2.0.1-2.3.10")) flag++;
if (rpm_check(release:"SLES12", cpu:"x86_64", reference:"sles12-salt-minion-image-2.0.1-2.3.14")) flag++;
if (rpm_check(release:"SLES12", cpu:"x86_64", reference:"sles12-sidecar-image-2.0.1-2.3.11")) flag++;
if (rpm_check(release:"SLES12", cpu:"x86_64", reference:"sles12-tiller-image-2.0.0-2.3.11")) flag++;
if (rpm_check(release:"SLES12", cpu:"x86_64", reference:"sles12-velum-image-2.0.1-2.3.13")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "CaaS Platform 2.0 images");
}
