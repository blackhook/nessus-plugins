#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:1292-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(148929);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/27");

  script_cve_id("CVE-2020-8025");

  script_name(english:"SUSE SLES15 Security Update : pcp (SUSE-SU-2021:1292-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for pcp fixes the following issues :

Fixed completely CVE-2020-8025 (bsc#1171883)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1123311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1171883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1181571"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20211292-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8cdf2a3"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2021-1292=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2021-1292=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2021-1292=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2021-1292=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_gui2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_gui2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_import1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_import1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_mmv1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_mmv1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_trace2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_trace2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_web1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_web1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-conf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-import-iostat2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-import-mrtg2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-import-sar2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PCP-LogImport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PCP-LogImport-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PCP-LogSummary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PCP-MMV");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PCP-MMV-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PCP-PMDA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PCP-PMDA-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-pcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "s390x") audit(AUDIT_ARCH_NOT, "s390x", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libpcp-devel-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libpcp3-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libpcp3-debuginfo-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libpcp_gui2-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libpcp_gui2-debuginfo-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libpcp_import1-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libpcp_import1-debuginfo-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libpcp_mmv1-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libpcp_mmv1-debuginfo-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libpcp_trace2-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libpcp_trace2-debuginfo-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libpcp_web1-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libpcp_web1-debuginfo-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"pcp-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"pcp-conf-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"pcp-debuginfo-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"pcp-debugsource-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"pcp-devel-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"pcp-devel-debuginfo-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"pcp-import-iostat2pcp-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"pcp-import-mrtg2pcp-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"pcp-import-sar2pcp-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"perl-PCP-LogImport-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"perl-PCP-LogImport-debuginfo-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"perl-PCP-LogSummary-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"perl-PCP-MMV-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"perl-PCP-MMV-debuginfo-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"perl-PCP-PMDA-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"perl-PCP-PMDA-debuginfo-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"python-pcp-3.11.9-5.11.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"python-pcp-debuginfo-3.11.9-5.11.5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pcp");
}
