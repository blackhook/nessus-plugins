#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0254-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106455);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-11423", "CVE-2017-12374", "CVE-2017-12375", "CVE-2017-12376", "CVE-2017-12377", "CVE-2017-12378", "CVE-2017-12379", "CVE-2017-12380", "CVE-2017-6418", "CVE-2017-6419", "CVE-2017-6420");

  script_name(english:"SUSE SLES11 Security Update : clamav (SUSE-SU-2018:0254-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for clamav fixes the following issues :

  - Update to security release 0.99.3 (bsc#1077732)

  - CVE-2017-12376 (ClamAV Buffer Overflow in handle_pdfname
    Vulnerability)

  - CVE-2017-12377 (ClamAV Mew Packet Heap Overflow
    Vulnerability)

  - CVE-2017-12379 (ClamAV Buffer Overflow in
    messageAddArgument Vulnerability)

  - these vulnerabilities could have allowed an
    unauthenticated, remote attacker to cause a denial of
    service (DoS) condition or potentially execute arbitrary
    code on an affected device.

  - CVE-2017-12374 (ClamAV use-after-free Vulnerabilities)

  - CVE-2017-12375 (ClamAV Buffer Overflow Vulnerability)

  - CVE-2017-12378 (ClamAV Buffer Over Read Vulnerability)

  - CVE-2017-12380 (ClamAV Null Dereference Vulnerability)

  - these vulnerabilities could have allowed an
    unauthenticated, remote attacker to cause a denial of
    service (DoS) condition on an affected device.

  - CVE-2017-6420 (bsc#1052448)

  - this vulnerability could have allowed remote attackers
    to cause a denial of service (use-after-free) via a
    crafted PE file with WWPack compression.

  - CVE-2017-6419 (bsc#1052449)

  - ClamAV could have allowed remote attackers to cause a
    denial of service (heap-based buffer overflow and
    application crash) or possibly have unspecified other
    impact via a crafted CHM file.

  - CVE-2017-11423 (bsc#1049423)

  - ClamAV could have allowed remote attackers to cause a
    denial of service (stack-based buffer over-read and
    application crash) via a crafted CAB file.

  - CVE-2017-6418 (bsc#1052466)

  - ClamAV could have allowed remote attackers to cause a
    denial of service (out-of-bounds read) via a crafted
    e-mail message.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1077732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11423/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12374/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12375/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12376/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12377/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12378/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12379/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12380/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6418/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6419/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6420/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180254-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8167c28d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-clamav-13445=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-clamav-13445=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-clamav-13445=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-clamav-13445=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-clamav-13445=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/29");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"clamav-0.99.3-0.20.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"clamav-0.99.3-0.20.3.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav");
}
