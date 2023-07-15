#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:3685-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(120161);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/16");

  script_cve_id("CVE-2018-15853", "CVE-2018-15854", "CVE-2018-15855", "CVE-2018-15856", "CVE-2018-15857", "CVE-2018-15858", "CVE-2018-15859", "CVE-2018-15861", "CVE-2018-15862", "CVE-2018-15863", "CVE-2018-15864");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : libxkbcommon (SUSE-SU-2018:3685-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libxkbcommon to version 0.8.2 fixes the following
issues :

Fix a few NULL-dereferences, out-of-bounds access and undefined
behavior in the XKB text format parser.

CVE-2018-15853: Endless recursion could have been used by local
attackers to crash xkbcommon users by supplying a crafted keymap file
that triggers boolean negation (bsc#1105832).

CVE-2018-15854: Unchecked NULL pointer usage could have been used by
local attackers to crash (NULL pointer dereference) the xkbcommon
parser by supplying a crafted keymap file, because geometry tokens
were desupported incorrectly (bsc#1105832).

CVE-2018-15855: Unchecked NULL pointer usage could have been used by
local attackers to crash (NULL pointer dereference) the xkbcommon
parser by supplying a crafted keymap file, because the XkbFile for an
xkb_geometry section was mishandled (bsc#1105832).

CVE-2018-15856: An infinite loop when reaching EOL unexpectedly could
be used by local attackers to cause a denial of service during parsing
of crafted keymap files (bsc#1105832).

CVE-2018-15857: An invalid free in ExprAppendMultiKeysymList could
have been used by local attackers to crash xkbcommon keymap parsers or
possibly have unspecified other impact by supplying a crafted keymap
file (bsc#1105832).

CVE-2018-15858: Unchecked NULL pointer usage when handling invalid
aliases in CopyKeyAliasesToKeymap could have been used by local
attackers to crash (NULL pointer dereference) the xkbcommon parser by
supplying a crafted keymap file (bsc#1105832).

CVE-2018-15859: Unchecked NULL pointer usage when parsing invalid
atoms in ExprResolveLhs could have been used by local attackers to
crash (NULL pointer dereference) the xkbcommon parser by supplying a
crafted keymap file, because lookup failures are mishandled
(bsc#1105832).

CVE-2018-15861: Unchecked NULL pointer usage in ExprResolveLhs could
have been used by local attackers to crash (NULL pointer dereference)
the xkbcommon parser by supplying a crafted keymap file that triggers
an xkb_intern_atom failure (bsc#1105832).

CVE-2018-15862: Unchecked NULL pointer usage in LookupModMask could
have been used by local attackers to crash (NULL pointer dereference)
the xkbcommon parser by supplying a crafted keymap file with invalid
virtual modifiers (bsc#1105832).

CVE-2018-15863: Unchecked NULL pointer usage in
ResolveStateAndPredicate could have been used by local attackers to
crash (NULL pointer dereference) the xkbcommon parser by supplying a
crafted keymap file with a no-op modmask expression (bsc#1105832).

CVE-2018-15864: Unchecked NULL pointer usage in resolve_keysym could
have been used by local attackers to crash (NULL pointer dereference)
the xkbcommon parser by supplying a crafted keymap file, because a map
access attempt can occur for a map that was never created
(bsc#1105832).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1105832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15853/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15854/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15855/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15856/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15857/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15858/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15859/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15861/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15862/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15863/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15864/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20183685-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75466d58"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2018-2620=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxkbcommon-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxkbcommon-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxkbcommon-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxkbcommon-x11-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxkbcommon-x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxkbcommon0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxkbcommon0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", reference:"libxkbcommon-debugsource-0.8.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libxkbcommon-devel-0.8.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libxkbcommon-x11-0-0.8.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libxkbcommon-x11-0-debuginfo-0.8.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libxkbcommon-x11-devel-0.8.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libxkbcommon0-0.8.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libxkbcommon0-debuginfo-0.8.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libxkbcommon-debugsource-0.8.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libxkbcommon-devel-0.8.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libxkbcommon-x11-0-0.8.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libxkbcommon-x11-0-debuginfo-0.8.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libxkbcommon-x11-devel-0.8.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libxkbcommon0-0.8.2-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libxkbcommon0-debuginfo-0.8.2-3.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxkbcommon");
}
