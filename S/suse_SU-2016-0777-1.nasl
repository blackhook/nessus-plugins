#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0777-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(89990);
  script_version("2.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2016-1950", "CVE-2016-1952", "CVE-2016-1953", "CVE-2016-1954", "CVE-2016-1957", "CVE-2016-1958", "CVE-2016-1960", "CVE-2016-1961", "CVE-2016-1962", "CVE-2016-1964", "CVE-2016-1965", "CVE-2016-1966", "CVE-2016-1974", "CVE-2016-1977", "CVE-2016-1978", "CVE-2016-1979", "CVE-2016-2790", "CVE-2016-2791", "CVE-2016-2792", "CVE-2016-2793", "CVE-2016-2794", "CVE-2016-2795", "CVE-2016-2796", "CVE-2016-2797", "CVE-2016-2798", "CVE-2016-2799", "CVE-2016-2800", "CVE-2016-2801", "CVE-2016-2802");

  script_name(english:"SUSE SLED11 / SLES11 Security Update : MozillaFirefox, mozilla-nspr, mozilla-nss (SUSE-SU-2016:0777-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaFirefox, mozilla-nspr, mozilla-nss fixes the
following issues :

Mozilla Firefox was updated to 38.7.0 ESR (bsc#969894)

  - MFSA 2016-16/CVE-2016-1952/CVE-2016-1953 Miscellaneous
    memory safety hazards (rv:45.0 / rv:38.7)

  - MFSA 2016-17/CVE-2016-1954 Local file overwriting and
    potential privilege escalation through CSP reports

  - MFSA 2016-20/CVE-2016-1957 A memory leak in
    libstagefright when deleting an array during MP4
    processing was fixed.

  - MFSA 2016-21/CVE-2016-1958 The displayed page address
    can be overridden

  - MFSA 2016-23/CVE-2016-1960 A use-after-free in HTML5
    string parser was fixed.

  - MFSA 2016-24/CVE-2016-1961 A use-after-free in SetBody
    was fixed.

  - MFSA 2016-25/CVE-2016-1962 A use-after-free when using
    multiple WebRTC data channels was fixed.

  - MFSA 2016-27/CVE-2016-1964 A use-after-free during XML
    transformations was fixed.

  - MFSA 2016-28/CVE-2016-1965 Addressbar spoofing though
    history navigation and Location protocol property was
    fixed.

  - MFSA 2016-31/CVE-2016-1966 Memory corruption with
    malicious NPAPI plugin was fixed.

  - MFSA 2016-34/CVE-2016-1974 A out-of-bounds read in the
    HTML parser following a failed allocation was fixed.

  - MFSA 2016-35/CVE-2016-1950 A buffer overflow during
    ASN.1 decoding in NSS was fixed.

  - MFSA 2016-37/CVE-2016-1977/CVE-2016-2790/CVE-2016-2791/
    CVE-2016-2792/CVE-2016-2793/CVE-2016-2794/CVE-2016-2795/
    CVE-2016-2796/CVE-2016-2797/CVE-2016-2798/CVE-2016-2799/
    CVE-2016-2800/CVE-2016-2801/CVE-2016-2802 Various font
    vulnerabilities were fixed in the embedded Graphite 2
    library

Mozilla NSS was updated to fix :

  - MFSA 2016-15/CVE-2016-1978 Use-after-free in NSS during
    SSL connections in low memory

  - MFSA 2016-35/CVE-2016-1950 Buffer overflow during ASN.1
    decoding in NSS

  - MFSA 2016-36/CVE-2016-1979 Use-after-free during
    processing of DER encoded keys in NSS

Mozilla NSPR was updated to version 4.12 (bsc#969894)

  - added a PR_GetEnvSecure function, which attempts to
    detect if the program is being executed with elevated
    privileges, and returns NULL if detected. It is
    recommended to use this function in general purpose
    library code.

  - fixed a memory allocation bug related to the PR_*printf
    functions

  - exported API PR_DuplicateEnvironment, which had already
    been added in NSPR 4.10.9

  - added support for FreeBSD aarch64

  - several minor correctness and compatibility fixes

  - Enable atomic instructions on mips (bmo#1129878)

  - Fix mips assertion failure when creating thread with
    custom stack size (bmo#1129968)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=969894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1950/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1952/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1953/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1954/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1957/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1958/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1960/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1961/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1962/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1964/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1965/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1966/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1974/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1977/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1978/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1979/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2790/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2791/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2792/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2793/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2794/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2795/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2796/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2797/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2798/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2799/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2800/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2801/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2802/"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160777-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90a5bfcb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-MozillaFirefox-20160309-12458=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-MozillaFirefox-20160309-12458=1

SUSE Linux Enterprise Server 11-SP3-LTSS :

zypper in -t patch slessp3-MozillaFirefox-20160309-12458=1

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-MozillaFirefox-20160309-12458=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-MozillaFirefox-20160309-12458=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-MozillaFirefox-20160309-12458=1

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/17");
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
if (os_ver == "SLES11" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libfreebl3-32bit-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libsoftokn3-32bit-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.12-24.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"mozilla-nss-32bit-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libfreebl3-32bit-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libsoftokn3-32bit-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"mozilla-nspr-32bit-4.12-24.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"mozilla-nss-32bit-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"MozillaFirefox-38.7.0esr-37.3")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"MozillaFirefox-translations-38.7.0esr-37.3")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libfreebl3-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libsoftokn3-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mozilla-nspr-4.12-24.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mozilla-nss-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mozilla-nss-tools-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libfreebl3-32bit-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libsoftokn3-32bit-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.12-24.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"mozilla-nss-32bit-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libfreebl3-32bit-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libsoftokn3-32bit-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"mozilla-nspr-32bit-4.12-24.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"mozilla-nss-32bit-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"MozillaFirefox-38.7.0esr-37.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"MozillaFirefox-translations-38.7.0esr-37.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libfreebl3-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libsoftokn3-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mozilla-nspr-4.12-24.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mozilla-nss-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mozilla-nss-tools-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"MozillaFirefox-38.7.0esr-37.3")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"MozillaFirefox-translations-38.7.0esr-37.3")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libfreebl3-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libsoftokn3-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mozilla-nspr-4.12-24.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mozilla-nss-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mozilla-nss-tools-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libfreebl3-32bit-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libsoftokn3-32bit-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.12-24.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mozilla-nss-32bit-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"MozillaFirefox-38.7.0esr-37.3")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"MozillaFirefox-translations-38.7.0esr-37.3")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libfreebl3-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libsoftokn3-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mozilla-nspr-4.12-24.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mozilla-nss-3.20.2-28.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mozilla-nss-tools-3.20.2-28.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / mozilla-nspr / mozilla-nss");
}
