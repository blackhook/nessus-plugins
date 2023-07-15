#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1150-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84442);
  script_version("2.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2015-1788",
    "CVE-2015-1789",
    "CVE-2015-1790",
    "CVE-2015-1791",
    "CVE-2015-1792",
    "CVE-2015-3216",
    "CVE-2015-4000"
  );
  script_bugtraq_id(
    74733,
    75154,
    75156,
    75157,
    75158,
    75161,
    75219
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : compat-openssl098 (SUSE-SU-2015:1150-1) (Logjam)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update fixes the following security issues :

  - CVE-2015-4000 (boo#931698)

  - The Logjam Attack / weakdh.org

  - reject connections with DH parameters shorter than 1024
    bits

  - generates 2048-bit DH parameters by default

  - CVE-2015-1788 (boo#934487)

  - Malformed ECParameters causes infinite loop

  - CVE-2015-1789 (boo#934489)

  - Exploitable out-of-bounds read in X509_cmp_time

  - CVE-2015-1790 (boo#934491)

  - PKCS7 crash with missing EnvelopedContent

  - CVE-2015-1792 (boo#934493)

  - CMS verify infinite loop with unknown hash function

  - CVE-2015-1791 (boo#933911)

  - race condition in NewSessionTicket

  - CVE-2015-3216 (boo#933898)

  - Crash in ssleay_rand_bytes due to locking regression

  - modified openssl-1.0.1i-fipslocking.patch

  - fix timing side channel in RSA decryption (bnc#929678)

  - add ECC ciphersuites to DEFAULT (bnc#879179)

  - Disable EXPORT ciphers by default (bnc#931698, comment
    #3)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=879179");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=929678");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=931698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=933898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=933911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=934487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=934489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=934491");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=934493");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-1788/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-1789/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-1790/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-1791/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-1792/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-3216/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4000/");
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151150-1.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4eea51db");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Legacy Software 12 :

zypper in -t patch SUSE-SLE-Module-Legacy-12-2015-285=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-285=1

To bring your system up-to-date, use 'zypper patch'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:compat-openssl098-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl0_9_8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl0_9_8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"compat-openssl098-debugsource-0.9.8j-78.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libopenssl0_9_8-0.9.8j-78.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libopenssl0_9_8-32bit-0.9.8j-78.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libopenssl0_9_8-debuginfo-0.9.8j-78.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libopenssl0_9_8-debuginfo-32bit-0.9.8j-78.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"compat-openssl098-debugsource-0.9.8j-78.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libopenssl0_9_8-0.9.8j-78.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libopenssl0_9_8-32bit-0.9.8j-78.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libopenssl0_9_8-debuginfo-0.9.8j-78.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libopenssl0_9_8-debuginfo-32bit-0.9.8j-78.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "compat-openssl098");
}
