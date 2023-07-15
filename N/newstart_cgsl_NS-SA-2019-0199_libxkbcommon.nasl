#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0199. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130201);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2018-15853",
    "CVE-2018-15854",
    "CVE-2018-15855",
    "CVE-2018-15856",
    "CVE-2018-15857",
    "CVE-2018-15859",
    "CVE-2018-15861",
    "CVE-2018-15862",
    "CVE-2018-15863",
    "CVE-2018-15864"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : libxkbcommon Multiple Vulnerabilities (NS-SA-2019-0199)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has libxkbcommon packages installed that are
affected by multiple vulnerabilities:

  - Unchecked NULL pointer usage in LookupModMask in
    xkbcomp/expr.c in xkbcommon before 0.8.2 could be used
    by local attackers to crash (NULL pointer dereference)
    the xkbcommon parser by supplying a crafted keymap file
    with invalid virtual modifiers. (CVE-2018-15862)

  - Unchecked NULL pointer usage in ResolveStateAndPredicate
    in xkbcomp/compat.c in xkbcommon before 0.8.2 could be
    used by local attackers to crash (NULL pointer
    dereference) the xkbcommon parser by supplying a crafted
    keymap file with a no-op modmask expression.
    (CVE-2018-15863)

  - Unchecked NULL pointer usage in resolve_keysym in
    xkbcomp/parser.y in xkbcommon before 0.8.2 could be used
    by local attackers to crash (NULL pointer dereference)
    the xkbcommon parser by supplying a crafted keymap file,
    because a map access attempt can occur for a map that
    was never created. (CVE-2018-15864)

  - Endless recursion exists in xkbcomp/expr.c in xkbcommon
    and libxkbcommon before 0.8.1, which could be used by
    local attackers to crash xkbcommon users by supplying a
    crafted keymap file that triggers boolean negation.
    (CVE-2018-15853)

  - Unchecked NULL pointer usage when parsing invalid atoms
    in ExprResolveLhs in xkbcomp/expr.c in xkbcommon before
    0.8.2 could be used by local attackers to crash (NULL
    pointer dereference) the xkbcommon parser by supplying a
    crafted keymap file, because lookup failures are
    mishandled. (CVE-2018-15859)

  - Unchecked NULL pointer usage in ExprResolveLhs in
    xkbcomp/expr.c in xkbcommon before 0.8.2 could be used
    by local attackers to crash (NULL pointer dereference)
    the xkbcommon parser by supplying a crafted keymap file
    that triggers an xkb_intern_atom failure.
    (CVE-2018-15861)

  - An invalid free in ExprAppendMultiKeysymList in
    xkbcomp/ast-build.c in xkbcommon before 0.8.1 could be
    used by local attackers to crash xkbcommon keymap
    parsers or possibly have unspecified other impact by
    supplying a crafted keymap file. (CVE-2018-15857)

  - An infinite loop when reaching EOL unexpectedly in
    compose/parser.c (aka the keymap parser) in xkbcommon
    before 0.8.1 could be used by local attackers to cause a
    denial of service during parsing of crafted keymap
    files. (CVE-2018-15856)

  - Unchecked NULL pointer usage in xkbcommon before 0.8.1
    could be used by local attackers to crash (NULL pointer
    dereference) the xkbcommon parser by supplying a crafted
    keymap file, because the XkbFile for an xkb_geometry
    section was mishandled. (CVE-2018-15855)

  - Unchecked NULL pointer usage in xkbcommon before 0.8.1
    could be used by local attackers to crash (NULL pointer
    dereference) the xkbcommon parser by supplying a crafted
    keymap file, because geometry tokens were desupported
    incorrectly. (CVE-2018-15854)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0199");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL libxkbcommon packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15857");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "libxkbcommon-0.7.1-3.el7",
    "libxkbcommon-debuginfo-0.7.1-3.el7",
    "libxkbcommon-devel-0.7.1-3.el7",
    "libxkbcommon-x11-0.7.1-3.el7",
    "libxkbcommon-x11-devel-0.7.1-3.el7"
  ],
  "CGSL MAIN 5.04": [
    "libxkbcommon-0.7.1-3.el7",
    "libxkbcommon-debuginfo-0.7.1-3.el7",
    "libxkbcommon-devel-0.7.1-3.el7",
    "libxkbcommon-x11-0.7.1-3.el7",
    "libxkbcommon-x11-devel-0.7.1-3.el7"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
