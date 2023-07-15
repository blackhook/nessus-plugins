#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2907-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104270);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2009-2699", "CVE-2010-0425", "CVE-2012-0021", "CVE-2014-0118", "CVE-2017-3167", "CVE-2017-3169", "CVE-2017-7668", "CVE-2017-7679", "CVE-2017-9798");
  script_bugtraq_id(36596, 38494, 51705, 68745);

  script_name(english:"SUSE SLES11 Security Update : apache2 (SUSE-SU-2017:2907-1) (Optionsbleed)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for apache2 fixes the following issues :

  - Allow disabling SNI on proxy connections using 'SetEnv
    proxy-disable-sni 1' in the configuration files.
    (bsc#1052830)

  - Allow ECDH again in mod_ssl, it had been incorrectly
    disabled with the 2.2.34 update. (bsc#1064561) Following
    security issue has been fixed :

  - CVE-2017-9798: A use-after-free in the OPTIONS command
    could be used by attackers to disclose memory of the
    apache server process, when htaccess uses incorrect
    Limit statement. (bsc#1058058) Additionally, references
    to the following security issues, fixed by the previous
    version-update of apache2 to Apache HTTPD 2.2.34 have
    been added :

  - CVE-2017-7668: The HTTP strict parsing introduced a bug
    in token list parsing, which allowed ap_find_token() to
    search past the end of its input string. By maliciously
    crafting a sequence of request headers, an attacker may
    have be able to cause a segmentation fault, or to force
    ap_find_token() to return an incorrect value.
    (bsc#1045061)

  - CVE-2017-3169: mod_ssl may have de-referenced a NULL
    pointer when third-party modules call
    ap_hook_process_connection() during an HTTP request to
    an HTTPS port allowing for DoS. (bsc#1045062)

  - CVE-2017-3167: Use of the ap_get_basic_auth_pw() by
    third-party modules outside of the authentication phase
    may have lead to authentication requirements being
    bypassed. (bsc#1045065)

  - CVE-2017-7679: mod_mime could have read one byte past
    the end of a buffer when sending a malicious
    Content-Type response header. (bsc#1045060)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1058058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2009-2699/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2010-0425/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2012-0021/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-0118/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3167/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3169/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7668/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7679/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9798/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172907-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?084963fe"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Studio Onsite 1.3:zypper in -t patch slestso13-apache2-13331=1

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-apache2-13331=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-apache2-13331=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-apache2-13331=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-apache2-13331=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-apache2-13331=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-apache2-13331=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/31");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SLES11", sp:"4", reference:"apache2-2.2.34-70.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"apache2-doc-2.2.34-70.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"apache2-example-pages-2.2.34-70.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"apache2-prefork-2.2.34-70.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"apache2-utils-2.2.34-70.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"apache2-worker-2.2.34-70.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"apache2-2.2.34-70.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"apache2-devel-2.2.34-70.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"apache2-doc-2.2.34-70.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"apache2-example-pages-2.2.34-70.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"apache2-prefork-2.2.34-70.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"apache2-utils-2.2.34-70.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"apache2-worker-2.2.34-70.12.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2");
}
