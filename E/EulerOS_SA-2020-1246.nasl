#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134535);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-15853",
    "CVE-2018-15857",
    "CVE-2018-15859",
    "CVE-2018-15861",
    "CVE-2018-15862",
    "CVE-2018-15863",
    "CVE-2018-15864"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : libxkbcommon (EulerOS-SA-2020-1246)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libxkbcommon package installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - Endless recursion exists in xkbcomp/expr.c in xkbcommon
    and libxkbcommon before 0.8.1, which could be used by
    local attackers to crash xkbcommon users by supplying a
    crafted keymap file that triggers boolean
    negation.(CVE-2018-15853)

  - Unchecked NULL pointer usage when parsing invalid atoms
    in ExprResolveLhs in xkbcomp/expr.c in xkbcommon before
    0.8.2 could be used by local attackers to crash (NULL
    pointer dereference) the xkbcommon parser by supplying
    a crafted keymap file, because lookup failures are
    mishandled.(CVE-2018-15859)

  - Unchecked NULL pointer usage in ExprResolveLhs in
    xkbcomp/expr.c in xkbcommon before 0.8.2 could be used
    by local attackers to crash (NULL pointer dereference)
    the xkbcommon parser by supplying a crafted keymap file
    that triggers an xkb_intern_atom
    failure.(CVE-2018-15861)

  - Unchecked NULL pointer usage in LookupModMask in
    xkbcomp/expr.c in xkbcommon before 0.8.2 could be used
    by local attackers to crash (NULL pointer dereference)
    the xkbcommon parser by supplying a crafted keymap file
    with invalid virtual modifiers.(CVE-2018-15862)

  - Unchecked NULL pointer usage in
    ResolveStateAndPredicate in xkbcomp/compat.c in
    xkbcommon before 0.8.2 could be used by local attackers
    to crash (NULL pointer dereference) the xkbcommon
    parser by supplying a crafted keymap file with a no-op
    modmask expression.(CVE-2018-15863)

  - Unchecked NULL pointer usage in resolve_keysym in
    xkbcomp/parser.y in xkbcommon before 0.8.2 could be
    used by local attackers to crash (NULL pointer
    dereference) the xkbcommon parser by supplying a
    crafted keymap file, because a map access attempt can
    occur for a map that was never created.(CVE-2018-15864)

  - An invalid free in ExprAppendMultiKeysymList in
    xkbcomp/ast-build.c in xkbcommon before 0.8.1 could be
    used by local attackers to crash xkbcommon keymap
    parsers or possibly have unspecified other impact by
    supplying a crafted keymap file.(CVE-2018-15857)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1246
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f60a3ff6");
  script_set_attribute(attribute:"solution", value:
"Update the affected libxkbcommon packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libxkbcommon");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["libxkbcommon-0.7.1-1.h1"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxkbcommon");
}
