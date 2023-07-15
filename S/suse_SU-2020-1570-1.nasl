#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1570-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(137599);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2015-9096",
    "CVE-2016-2339",
    "CVE-2016-7798",
    "CVE-2017-0898",
    "CVE-2017-0899",
    "CVE-2017-0900",
    "CVE-2017-0901",
    "CVE-2017-0902",
    "CVE-2017-0903",
    "CVE-2017-9228",
    "CVE-2017-9229",
    "CVE-2017-10784",
    "CVE-2017-14033",
    "CVE-2017-14064",
    "CVE-2017-17405",
    "CVE-2017-17742",
    "CVE-2017-17790",
    "CVE-2018-6914",
    "CVE-2018-8777",
    "CVE-2018-8778",
    "CVE-2018-8779",
    "CVE-2018-8780",
    "CVE-2018-16395",
    "CVE-2018-16396",
    "CVE-2018-1000073",
    "CVE-2018-1000074",
    "CVE-2018-1000075",
    "CVE-2018-1000076",
    "CVE-2018-1000077",
    "CVE-2018-1000078",
    "CVE-2018-1000079",
    "CVE-2019-8320",
    "CVE-2019-8321",
    "CVE-2019-8322",
    "CVE-2019-8323",
    "CVE-2019-8324",
    "CVE-2019-8325",
    "CVE-2019-15845",
    "CVE-2019-16201",
    "CVE-2019-16254",
    "CVE-2019-16255",
    "CVE-2020-10663"
  );

  script_name(english:"SUSE SLES12 Security Update : ruby2.1 (SUSE-SU-2020:1570-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for ruby2.1 fixes the following issues :

Security issues fixed :

CVE-2015-9096: Fixed an SMTP command injection via CRLFsequences in a
RCPT TO or MAIL FROM command (bsc#1043983).

CVE-2016-7798: Fixed an IV Reuse in GCM Mode (bsc#1055265).

CVE-2017-0898: Fixed a buffer underrun vulnerability in Kernel.sprintf
(bsc#1058755).

CVE-2017-0899: Fixed an issue with malicious gem specifications,
insufficient sanitation when printing gem specifications could have
included terminal characters (bsc#1056286).

CVE-2017-0900: Fixed an issue with malicious gem specifications, the
query command could have led to a denial of service attack against
clients (bsc#1056286).

CVE-2017-0901: Fixed an issue with malicious gem specifications,
potentially overwriting arbitrary files on the client system
(bsc#1056286).

CVE-2017-0902: Fixed an issue with malicious gem specifications, that
could have enabled MITM attacks against clients (bsc#1056286).

CVE-2017-0903: Fixed an unsafe object deserialization vulnerability
(bsc#1062452).

CVE-2017-9228: Fixed a heap out-of-bounds write in bitset_set_range()
during regex compilation (bsc#1069607).

CVE-2017-9229: Fixed an invalid pointer dereference in
left_adjust_char_head() in oniguruma (bsc#1069632).

CVE-2017-10784: Fixed an escape sequence injection vulnerability in
the Basic authentication of WEBrick (bsc#1058754).

CVE-2017-14033: Fixed a buffer underrun vulnerability in OpenSSL ASN1
decode (bsc#1058757).

CVE-2017-14064: Fixed an arbitrary memory exposure during a
JSON.generate call (bsc#1056782).

CVE-2017-17405: Fixed a command injection vulnerability in Net::FTP
(bsc#1073002).

CVE-2017-17742: Fixed an HTTP response splitting issue in WEBrick
(bsc#1087434).

CVE-2017-17790: Fixed a command injection in
lib/resolv.rb:lazy_initialize() (bsc#1078782).

CVE-2018-6914: Fixed an unintentional file and directory creation with
directory traversal in tempfile and tmpdir (bsc#1087441).

CVE-2018-8777: Fixed a potential DoS caused by large requests in
WEBrick (bsc#1087436).

CVE-2018-8778: Fixed a buffer under-read in String#unpack
(bsc#1087433).

CVE-2018-8779: Fixed an unintentional socket creation by poisoned NUL
byte in UNIXServer and UNIXSocket (bsc#1087440).

CVE-2018-8780: Fixed an unintentional directory traversal by poisoned
NUL byte in Dir (bsc#1087437).

CVE-2018-16395: Fixed an issue with OpenSSL::X509::Name equality
checking (bsc#1112530).

CVE-2018-16396: Fixed an issue with tainted string handling, where the
flag was not propagated in Array#pack and String#unpack with some
directives (bsc#1112532).

CVE-2018-1000073: Fixed a path traversal issue (bsc#1082007).

CVE-2018-1000074: Fixed an unsafe object deserialization vulnerability
in gem owner, allowing arbitrary code execution with specially crafted
YAML (bsc#1082008).

CVE-2018-1000075: Fixed an infinite loop vulnerability due to negative
size in tar header causes Denial of Service (bsc#1082014).

CVE-2018-1000076: Fixed an improper verification of signatures in
tarballs (bsc#1082009).

CVE-2018-1000077: Fixed an improper URL validation in the homepage
attribute of ruby gems (bsc#1082010).

CVE-2018-1000078: Fixed a XSS vulnerability in the homepage attribute
when displayed via gem server (bsc#1082011).

CVE-2018-1000079: Fixed a path traversal issue during gem installation
allows to write to arbitrary filesystem locations (bsc#1082058).

CVE-2019-8320: Fixed a directory traversal issue when decompressing
tar files (bsc#1130627).

CVE-2019-8321: Fixed an escape sequence injection vulnerability in
verbose (bsc#1130623).

CVE-2019-8322: Fixed an escape sequence injection vulnerability in gem
owner (bsc#1130622).

CVE-2019-8323: Fixed an escape sequence injection vulnerability in API
response handling (bsc#1130620).

CVE-2019-8324: Fixed an issue with malicious gems that may have led to
arbitrary code execution (bsc#1130617).

CVE-2019-8325: Fixed an escape sequence injection vulnerability in
errors (bsc#1130611).

CVE-2019-15845: Fixed a NUL injection vulnerability in File.fnmatch
and File.fnmatch? (bsc#1152994).

CVE-2019-16201: Fixed a regular expression denial of service
vulnerability in WEBrick's digest access authentication (bsc#1152995).

CVE-2019-16254: Fixed an HTTP response splitting vulnerability in
WEBrick (bsc#1152992).

CVE-2019-16255: Fixed a code injection vulnerability in Shell#[] and
Shell#test (bsc#1152990).

CVE-2020-10663: Fixed an unsafe object creation vulnerability in JSON
(bsc#1171517).

Non-security issue fixed :

Add conflicts to libruby to make sure ruby and ruby-stdlib are also
updated when libruby is updated (bsc#1048072).

Also yast2-ruby-bindings on SLES 12 SP2 LTSS was updated to handle the
updated ruby interpreter. (bsc#1172275)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1043983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1048072");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1055265");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1056286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1056782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1058754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1058755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1058757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1062452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1069607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1069632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1073002");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1078782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1082007");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1082008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1082009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1082010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1082011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1082014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1082058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1087433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1087434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1087436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1087437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1087440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1087441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1112530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1112532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1130611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1130617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1130620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1130622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1130623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1130627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1152990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1152992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1152994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1152995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171517");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172275");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-9096/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-2339/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-7798/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-0898/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-0899/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-0900/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-0901/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-0902/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-0903/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-10784/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-14033/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-14064/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-17405/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-17742/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-17790/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-9228/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-9229/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1000073/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1000074/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1000075/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1000076/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1000077/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1000078/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1000079/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16395/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16396/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-6914/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-8777/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-8778/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-8779/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-8780/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15845/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-16201/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-16254/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-16255/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8320/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8321/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8322/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8323/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8324/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8325/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10663/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201570-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d525cde");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 8 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-8-2020-1570=1

SUSE OpenStack Cloud 8 :

zypper in -t patch SUSE-OpenStack-Cloud-8-2020-1570=1

SUSE OpenStack Cloud 7 :

zypper in -t patch SUSE-OpenStack-Cloud-7-2020-1570=1

SUSE Linux Enterprise Software Development Kit 12-SP5 :

zypper in -t patch SUSE-SLE-SDK-12-SP5-2020-1570=1

SUSE Linux Enterprise Software Development Kit 12-SP4 :

zypper in -t patch SUSE-SLE-SDK-12-SP4-2020-1570=1

SUSE Linux Enterprise Server for SAP 12-SP3 :

zypper in -t patch SUSE-SLE-SAP-12-SP3-2020-1570=1

SUSE Linux Enterprise Server for SAP 12-SP2 :

zypper in -t patch SUSE-SLE-SAP-12-SP2-2020-1570=1

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2020-1570=1

SUSE Linux Enterprise Server 12-SP4 :

zypper in -t patch SUSE-SLE-SERVER-12-SP4-2020-1570=1

SUSE Linux Enterprise Server 12-SP3-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-2020-1570=1

SUSE Linux Enterprise Server 12-SP3-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-BCL-2020-1570=1

SUSE Linux Enterprise Server 12-SP2-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-2020-1570=1

SUSE Linux Enterprise Server 12-SP2-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-BCL-2020-1570=1

SUSE Enterprise Storage 5 :

zypper in -t patch SUSE-Storage-5-2020-1570=1

HPE Helion Openstack 8 :

zypper in -t patch HPE-Helion-OpenStack-8-2020-1570=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-17405");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-16395");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libruby2_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libruby2_1-2_1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.1-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.1-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.1-stdlib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:yast2-ruby-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:yast2-ruby-bindings-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:yast2-ruby-bindings-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"libruby2_1-2_1-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libruby2_1-2_1-debuginfo-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"ruby2.1-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"ruby2.1-debuginfo-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"ruby2.1-debugsource-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"ruby2.1-stdlib-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"ruby2.1-stdlib-debuginfo-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libruby2_1-2_1-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libruby2_1-2_1-debuginfo-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ruby2.1-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ruby2.1-debuginfo-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ruby2.1-debugsource-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ruby2.1-stdlib-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ruby2.1-stdlib-debuginfo-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libruby2_1-2_1-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libruby2_1-2_1-debuginfo-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ruby2.1-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ruby2.1-debuginfo-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ruby2.1-debugsource-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ruby2.1-stdlib-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ruby2.1-stdlib-debuginfo-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"yast2-ruby-bindings-3.1.53-9.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"yast2-ruby-bindings-debuginfo-3.1.53-9.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"yast2-ruby-bindings-debugsource-3.1.53-9.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libruby2_1-2_1-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libruby2_1-2_1-debuginfo-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"ruby2.1-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"ruby2.1-debuginfo-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"ruby2.1-debugsource-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"ruby2.1-stdlib-2.1.9-19.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"ruby2.1-stdlib-debuginfo-2.1.9-19.3.2")) flag++;


if (flag)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby2.1");
}
