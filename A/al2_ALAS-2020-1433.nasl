#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1433.
#

include("compat.inc");

if (description)
{
  script_id(137090);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/09");

  script_cve_id("CVE-2018-14598", "CVE-2018-14599", "CVE-2018-14600", "CVE-2018-15853", "CVE-2018-15854", "CVE-2018-15855", "CVE-2018-15856", "CVE-2018-15857", "CVE-2018-15859", "CVE-2018-15861", "CVE-2018-15862", "CVE-2018-15863", "CVE-2018-15864");
  script_xref(name:"ALAS", value:"2020-1433");

  script_name(english:"Amazon Linux 2 : xorg-x11-server (ALAS-2020-1433)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It was discovered that libX11 does not properly validate input coming
from the server, causing XListExtensions() and XGetFontPath()
functions to produce an invalid list of elements that in turn make
XFreeExtensionsList() and XFreeFontPath() access invalid memory. An
attacker who can either configure a malicious X server or modify the
data coming from one, could use this flaw to crash the application
using libX11, resulting in a denial of service.(CVE-2018-14598)

An off-by-one error has been discovered in libX11 in functions
XGetFontPath(), XListExtensions(), and XListFonts(). An attacker who
can either configure a malicious X server or modify the data coming
from one could use this flaw to make the program crash or have other
unspecified effects, caused by the memory corruption.(CVE-2018-14599)

An out of bounds write, limited to NULL bytes, was discovered in
libX11 in functions XListExtensions() and XGetFontPath(). The length
field is considered as a signed value, which makes the library access
memory before the intended buffer. An attacker who can either
configure a malicious X server or modify the data coming from one
could use this flaw to make the program crash or have other
unspecified effects, caused by the memory corruption.(CVE-2018-14600)

An uncontrolled recursion flaw was found in libxkbcommon in the way it
parses boolean expressions. A specially crafted file provided to
xkbcomp could crash the application. (CVE-2018-15853)

Unchecked NULL pointer usage in xkbcommon before 0.8.1 could be used
by local attackers to crash (NULL pointer dereference) the xkbcommon
parser by supplying a crafted keymap file, because geometry tokens
were desupported incorrectly. (CVE-2018-15854)

Unchecked NULL pointer usage in xkbcommon before 0.8.1 could be used
by local attackers to crash (NULL pointer dereference) the xkbcommon
parser by supplying a crafted keymap file, because the XkbFile for an
xkb_geometry section was mishandled. (CVE-2018-15855)

An infinite loop when reaching EOL unexpectedly in compose/parser.c
(aka the keymap parser) in xkbcommon before 0.8.1 could be used by
local attackers to cause a denial of service during parsing of crafted
keymap files. (CVE-2018-15856)

An invalid free in ExprAppendMultiKeysymList in xkbcomp/ast-build.c in
xkbcommon before 0.8.1 could be used by local attackers to crash
xkbcommon keymap parsers or possibly have unspecified other impact by
supplying a crafted keymap file. (CVE-2018-15857)

Unchecked NULL pointer usage when parsing invalid atoms in
ExprResolveLhs in xkbcomp/expr.c in xkbcommon before 0.8.2 could be
used by local attackers to crash (NULL pointer dereference) the
xkbcommon parser by supplying a crafted keymap file, because lookup
failures are mishandled. (CVE-2018-15859)

Unchecked NULL pointer usage in ExprResolveLhs in xkbcomp/expr.c in
xkbcommon before 0.8.2 could be used by local attackers to crash (NULL
pointer dereference) the xkbcommon parser by supplying a crafted
keymap file that triggers an xkb_intern_atom failure. (CVE-2018-15861)

Unchecked NULL pointer usage in LookupModMask in xkbcomp/expr.c in
xkbcommon before 0.8.2 could be used by local attackers to crash (NULL
pointer dereference) the xkbcommon parser by supplying a crafted
keymap file with invalid virtual modifiers. (CVE-2018-15862)

Unchecked NULL pointer usage in ResolveStateAndPredicate in
xkbcomp/compat.c in xkbcommon before 0.8.2 could be used by local
attackers to crash (NULL pointer dereference) the xkbcommon parser by
supplying a crafted keymap file with a no-op modmask expression.
(CVE-2018-15863)

Unchecked NULL pointer usage in resolve_keysym in xkbcomp/parser.y in
xkbcommon before 0.8.2 could be used by local attackers to crash (NULL
pointer dereference) the xkbcommon parser by supplying a crafted
keymap file, because a map access attempt can occur for a map that was
never created. (CVE-2018-15864)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1433.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update xorg-x11-server' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-Xwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"xorg-x11-server-Xdmx-1.20.4-7.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"xorg-x11-server-Xephyr-1.20.4-7.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"xorg-x11-server-Xnest-1.20.4-7.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"xorg-x11-server-Xorg-1.20.4-7.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"xorg-x11-server-Xvfb-1.20.4-7.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"xorg-x11-server-Xwayland-1.20.4-7.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"xorg-x11-server-common-1.20.4-7.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"xorg-x11-server-debuginfo-1.20.4-7.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"xorg-x11-server-devel-1.20.4-7.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"xorg-x11-server-source-1.20.4-7.amzn2.0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server-Xdmx / xorg-x11-server-Xephyr / etc");
}
