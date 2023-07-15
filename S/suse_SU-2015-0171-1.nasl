#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0171-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(83676);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2014-1569", "CVE-2014-8634", "CVE-2014-8636", "CVE-2014-8637", "CVE-2014-8638", "CVE-2014-8639", "CVE-2014-8640", "CVE-2014-8641");
  script_bugtraq_id(71675, 72041, 72044, 72045, 72046, 72047, 72048, 72049);

  script_name(english:"SUSE SLES10 Security Update : Mozilla Firefox (SUSE-SU-2015:0171-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox has been updated to the 31.4.0ESR release, fixing bugs
and security issues.

Mozilla NSS has been updated to 3.17.3, fixing a security issue and
updating the root certificate list.

For more information, please see
https://www.mozilla.org/en-US/security/advisories/

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=909563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=910647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=910669"
  );
  # https://download.suse.com/patch/finder/?keywords=b6b2353659cdca6dc3d8d5d591e00851
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8ad6a431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-1569/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8634/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8636/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8637/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8638/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8639/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8640/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8641/"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150171-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51e5995f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Mozilla Firefox packages"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox Proxy Prototype Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
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
if (! preg(pattern:"^(SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES10" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"mozilla-nss-32bit-3.17.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"mozilla-nss-32bit-3.17.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"mozilla-nss-3.17.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"mozilla-nss-devel-3.17.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"mozilla-nss-tools-3.17.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"MozillaFirefox-31.4.0esr-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"MozillaFirefox-translations-31.4.0esr-0.5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Firefox");
}
