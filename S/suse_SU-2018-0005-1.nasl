#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0005-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(105538);
  script_version("3.5");
  script_cvs_date("Date: 2019/09/10 13:51:46");

  script_cve_id("CVE-2016-10165", "CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9842", "CVE-2016-9843", "CVE-2017-10053", "CVE-2017-10067", "CVE-2017-10074", "CVE-2017-10081", "CVE-2017-10086", "CVE-2017-10087", "CVE-2017-10089", "CVE-2017-10090", "CVE-2017-10096", "CVE-2017-10101", "CVE-2017-10102", "CVE-2017-10105", "CVE-2017-10107", "CVE-2017-10108", "CVE-2017-10109", "CVE-2017-10110", "CVE-2017-10111", "CVE-2017-10114", "CVE-2017-10115", "CVE-2017-10116", "CVE-2017-10118", "CVE-2017-10125", "CVE-2017-10135", "CVE-2017-10176", "CVE-2017-10193", "CVE-2017-10198", "CVE-2017-10243", "CVE-2017-10274", "CVE-2017-10281", "CVE-2017-10285", "CVE-2017-10295", "CVE-2017-10345", "CVE-2017-10346", "CVE-2017-10347", "CVE-2017-10348", "CVE-2017-10349", "CVE-2017-10350", "CVE-2017-10355", "CVE-2017-10356", "CVE-2017-10357", "CVE-2017-10388");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : java-1_7_0-openjdk (SUSE-SU-2018:0005-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-1_7_0-openjdk fixes the following issues:
Security issues fixed :

  - CVE-2017-10356: Fix issue inside subcomponent Security
    (bsc#1064084).

  - CVE-2017-10274: Fix issue inside subcomponent Smart Card
    IO (bsc#1064071).

  - CVE-2017-10281: Fix issue inside subcomponent
    Serialization (bsc#1064072).

  - CVE-2017-10285: Fix issue inside subcomponent RMI
    (bsc#1064073).

  - CVE-2017-10295: Fix issue inside subcomponent Networking
    (bsc#1064075).

  - CVE-2017-10388: Fix issue inside subcomponent Libraries
    (bsc#1064086).

  - CVE-2017-10346: Fix issue inside subcomponent Hotspot
    (bsc#1064078).

  - CVE-2017-10350: Fix issue inside subcomponent JAX-WS
    (bsc#1064082).

  - CVE-2017-10347: Fix issue inside subcomponent
    Serialization (bsc#1064079).

  - CVE-2017-10349: Fix issue inside subcomponent JAXP
    (bsc#1064081).

  - CVE-2017-10345: Fix issue inside subcomponent
    Serialization (bsc#1064077).

  - CVE-2017-10348: Fix issue inside subcomponent Libraries
    (bsc#1064080).

  - CVE-2017-10357: Fix issue inside subcomponent
    Serialization (bsc#1064085).

  - CVE-2017-10355: Fix issue inside subcomponent Networking
    (bsc#1064083).

  - CVE-2017-10102: Fix incorrect handling of references in
    DGC (bsc#1049316).

  - CVE-2017-10053: Fix reading of unprocessed image data in
    JPEGImageReader (bsc#1049305).

  - CVE-2017-10067: Fix JAR verifier incorrect handling of
    missing digest (bsc#1049306).

  - CVE-2017-10081: Fix incorrect bracket processing in
    function signature handling (bsc#1049309).

  - CVE-2017-10087: Fix insufficient access control checks
    in ThreadPoolExecutor (bsc#1049311).

  - CVE-2017-10089: Fix insufficient access control checks
    in ServiceRegistry (bsc#1049312).

  - CVE-2017-10090: Fix insufficient access control checks
    in AsynchronousChannelGroupImpl (bsc#1049313).

  - CVE-2017-10096: Fix insufficient access control checks
    in XML transformations (bsc#1049314).

  - CVE-2017-10101: Fix unrestricted access to
    com.sun.org.apache.xml.internal.resolver (bsc#1049315).

  - CVE-2017-10107: Fix insufficient access control checks
    in ActivationID (bsc#1049318).

  - CVE-2017-10074: Fix integer overflows in range check
    loop predicates (bsc#1049307).

  - CVE-2017-10110: Fix insufficient access control checks
    in ImageWatched (bsc#1049321).

  - CVE-2017-10108: Fix unbounded memory allocation in
    BasicAttribute deserialization (bsc#1049319).

  - CVE-2017-10109: Fix unbounded memory allocation in
    CodeSource deserialization (bsc#1049320).

  - CVE-2017-10115: Fix unspecified vulnerability in
    subcomponent JCE (bsc#1049324).

  - CVE-2017-10118: Fix ECDSA implementation timing attack
    (bsc#1049326).

  - CVE-2017-10116: Fix LDAPCertStore following referrals to
    non-LDAP URL (bsc#1049325).

  - CVE-2017-10135: Fix PKCS#8 implementation timing attack
    (bsc#1049328).

  - CVE-2017-10176: Fix incorrect handling of certain EC
    points (bsc#1049329).

  - CVE-2017-10074: Fix integer overflows in range check
    loop predicates (bsc#1049307).

  - CVE-2017-10074: Fix integer overflows in range check
    loop predicates (bsc#1049307).

  - CVE-2017-10111: Fix checks in LambdaFormEditor
    (bsc#1049322).

  - CVE-2017-10243: Fix unspecified vulnerability in
    subcomponent JAX-WS (bsc#1049332).

  - CVE-2017-10125: Fix unspecified vulnerability in
    subcomponent deployment (bsc#1049327).

  - CVE-2017-10114: Fix unspecified vulnerability in
    subcomponent JavaFX (bsc#1049323).

  - CVE-2017-10105: Fix unspecified vulnerability in
    subcomponent deployment (bsc#1049317).

  - CVE-2017-10086: Fix unspecified in subcomponent JavaFX
    (bsc#1049310).

  - CVE-2017-10198: Fix incorrect enforcement of certificate
    path restrictions (bsc#1049331).

  - CVE-2017-10193: Fix incorrect key size constraint check
    (bsc#1049330). Bug fixes :

  - Drop Exec Shield workaround to fix crashes on recent
    kernels, where Exec Shield is gone (bsc#1052318).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049316"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049326"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049328"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049329"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10165/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9840/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9841/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9842/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9843/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10053/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10067/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10074/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10081/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10086/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10087/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10089/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10090/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10096/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10101/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10102/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10105/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10107/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10108/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10109/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10110/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10111/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10114/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10115/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10116/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10118/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10125/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10135/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10176/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10193/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10198/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10243/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10274/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10281/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10285/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10295/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10345/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10346/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10347/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10348/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10349/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10350/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10355/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10356/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10357/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10388/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180005-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a779e6a4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 6:zypper in -t patch
SUSE-OpenStack-Cloud-6-2018-6=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2018-6=1

SUSE Linux Enterprise Server for SAP 12:zypper in -t patch
SUSE-SLE-SAP-12-2018-6=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2018-6=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-6=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-6=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2018-6=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2018-6=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-6=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2018-6=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/04");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0|1|2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1/2/3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-debugsource-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-demo-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-devel-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-headless-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-debugsource-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-demo-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-devel-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-headless-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_7_0-openjdk-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_7_0-openjdk-debugsource-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_7_0-openjdk-demo-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_7_0-openjdk-devel-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_7_0-openjdk-headless-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_7_0-openjdk-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_7_0-openjdk-debugsource-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_7_0-openjdk-demo-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_7_0-openjdk-devel-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_7_0-openjdk-headless-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_7_0-openjdk-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_7_0-openjdk-debugsource-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_7_0-openjdk-headless-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-debugsource-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-headless-1.7.0.161-43.7.6")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.161-43.7.6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_7_0-openjdk");
}
