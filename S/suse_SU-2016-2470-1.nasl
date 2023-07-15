#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2470-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119982);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/27");

  script_cve_id(
    "CVE-2016-2178",
    "CVE-2016-2183",
    "CVE-2016-5325",
    "CVE-2016-6304",
    "CVE-2016-6306",
    "CVE-2016-7052",
    "CVE-2016-7099"
  );

  script_name(english:"SUSE SLES12 Security Update : nodejs4 (SUSE-SU-2016:2470-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update brings the new upstream nodejs LTS version 4.6.0, fixing
bugs and security issues :

  - Nodejs embedded openssl version update

  + upgrade to 1.0.2j (CVE-2016-6304, CVE-2016-2183,
    CVE-2016-2178, CVE-2016-6306, CVE-2016-7052)

  + remove support for dynamic 3rd party engine modules

- http: Properly validate for allowable characters in input user data.
This introduces a new case where throw may occur when configuring HTTP
responses, users should already be adopting try/catch here.
  (CVE-2016-5325, bsc#985201)

  - tls: properly validate wildcard certificates
    (CVE-2016-7099, bsc#1001652)

  - buffer: Zero-fill excess bytes in new Buffer objects
    created with Buffer.concat()

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1001652");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=985201");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-2178/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-2183/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-5325/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-6304/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-6306/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-7052/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-7099/");
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162470-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20d40afc");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Web Scripting 12:zypper in -t patch
SUSE-SLE-Module-Web-Scripting-12-2016-1439=1

To bring your system up-to-date, use 'zypper patch'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2183");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:npm4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"nodejs4-4.6.0-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"nodejs4-debuginfo-4.6.0-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"nodejs4-debugsource-4.6.0-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"nodejs4-devel-4.6.0-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"npm4-4.6.0-8.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs4");
}
