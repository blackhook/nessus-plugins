#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1604-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93154);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-8806", "CVE-2016-1762", "CVE-2016-1833", "CVE-2016-1834", "CVE-2016-1835", "CVE-2016-1837", "CVE-2016-1838", "CVE-2016-1839", "CVE-2016-1840", "CVE-2016-2073", "CVE-2016-3705", "CVE-2016-4447", "CVE-2016-4448", "CVE-2016-4449", "CVE-2016-4483");

  script_name(english:"SUSE SLES11 Security Update : libxml2 (SUSE-SU-2016:1604-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libxml2 fixes the following security issues :

  - CVE-2016-2073, CVE-2015-8806, CVE-2016-1839: A
    Heap-buffer overread was fixed in libxml2/dict.c
    [bsc#963963, bsc#965283, bsc#981114].

  - CVE-2016-4483: Code was added to avoid an out of bound
    access when serializing malformed strings [bsc#978395].

  - CVE-2016-1762: Fixed a heap-based buffer overread in
    xmlNextChar [bsc#981040].

  - CVE-2016-1834: Fixed a heap-buffer-overflow in
    xmlStrncat [bsc#981041].

  - CVE-2016-1833: Fixed a heap-based buffer overread in
    htmlCurrentChar [bsc#981108].

  - CVE-2016-1835: Fixed a heap use-after-free in
    xmlSAX2AttributeNs [bsc#981109].

  - CVE-2016-1837: Fixed a heap use-after-free in
    htmlParsePubidLiteral and htmlParseSystemiteral
    [bsc#981111].

  - CVE-2016-1838: Fixed a heap-based buffer overread in
    xmlParserPrintFileContextInternal [bsc#981112].

  - CVE-2016-1840: Fixed a heap-buffer-overflow in
    xmlFAParsePosCharGroup [bsc#981115].

  - CVE-2016-4447: Fixed a heap-based buffer-underreads due
    to xmlParseName [bsc#981548].

  - CVE-2016-4448: Fixed some format string warnings with
    possible format string vulnerability [bsc#981549],

  - CVE-2016-4449: Fixed inappropriate fetch of entities
    content [bsc#981550].

  - CVE-2016-3705: Fixed missing increment of recursion
    counter.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=963963"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=965283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=978395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8806/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1762/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1833/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1834/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1835/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1837/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1838/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1839/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1840/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2073/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3705/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4447/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4448/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4449/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4483/"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161604-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?408e371e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 5 :

zypper in -t patch sleclo50sp3-libxml2-12616=1

SUSE Manager Proxy 2.1 :

zypper in -t patch slemap21-libxml2-12616=1

SUSE Manager 2.1 :

zypper in -t patch sleman21-libxml2-12616=1

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-libxml2-12616=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-libxml2-12616=1

SUSE Linux Enterprise Server 11-SP3-LTSS :

zypper in -t patch slessp3-libxml2-12616=1

SUSE Linux Enterprise Server 11-SP2-LTSS :

zypper in -t patch slessp2-libxml2-12616=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-libxml2-12616=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-libxml2-12616=1

SUSE Linux Enterprise Debuginfo 11-SP2 :

zypper in -t patch dbgsp2-libxml2-12616=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(2|3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2/3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libxml2-32bit-2.7.6-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libxml2-32bit-2.7.6-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libxml2-2.7.6-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libxml2-doc-2.7.6-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libxml2-python-2.7.6-0.44.4")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libxml2-32bit-2.7.6-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libxml2-32bit-2.7.6-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libxml2-2.7.6-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libxml2-doc-2.7.6-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libxml2-python-2.7.6-0.44.4")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"libxml2-32bit-2.7.6-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"libxml2-32bit-2.7.6-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libxml2-2.7.6-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libxml2-doc-2.7.6-0.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libxml2-python-2.7.6-0.44.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2");
}
