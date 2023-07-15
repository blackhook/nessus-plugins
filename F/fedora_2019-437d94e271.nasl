#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-437d94e271.
#

include("compat.inc");

if (description)
{
  script_id(132644);
  script_version("1.4");
  script_cvs_date("Date: 2020/01/31");

  script_cve_id("CVE-2019-11044", "CVE-2019-11045", "CVE-2019-11046", "CVE-2019-11047", "CVE-2019-11049", "CVE-2019-11050");
  script_xref(name:"FEDORA", value:"2019-437d94e271");

  script_name(english:"Fedora 30 : php (2019-437d94e271)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**PHP version 7.3.13** (18 Dec 2019)

**Bcmath:**

  - Fixed bug php#78878 (Buffer underflow in
    bc_shift_addsub). (**CVE-2019-11046**). (cmb)

**Core:**

  - Fixed bug php#78862 (link() silently truncates after a
    null byte on Windows). (**CVE-2019-11044**). (cmb)

  - Fixed bug php#78863 (DirectoryIterator class silently
    truncates after a null byte). (**CVE-2019-11045**).
    (cmb)

  - Fixed bug php#78943 (mail() may release string with
    refcount==1 twice). (**CVE-2019-11049**). (cmb)

  - Fixed bug php#78787 (Segfault with trait overriding
    inherited private shadow property). (Nikita)

  - Fixed bug php#78868 (Calling __autoload() with incorrect
    EG(fake_scope) value). (Antony Dovgal, Dmitry)

  - Fixed bug php#78296 (is_file fails to detect file).
    (cmb)

**EXIF:**

  - Fixed bug php#78793 (Use-after-free in exif parsing
    under memory sanitizer). (**CVE-2019-11050**). (Nikita)

  - Fixed bug php#78910 (Heap-buffer-overflow READ in exif).
    (**CVE-2019-11047**). (Nikita)

**GD:**

  - Fixed bug php#78849 (GD build broken with -D
    SIGNED_COMPARE_SLOW). (cmb)

**MBString:**

  - Upgraded bundled Oniguruma to 6.9.4. (cmb)

**OPcache:**

  - Fixed potential ASLR related invalid opline handler
    issues. (cmb)

  - Fixed $x = (bool)$x; with opcache (should emit
    undeclared variable notice). (Tyson Andre)

**PCRE:**

  - Fixed bug php#78853 (preg_match() may return integer >
    1). (cmb)

**Standard:**

  - Fixed bug php#78759 (array_search in $GLOBALS). (Nikita)

  - Fixed bug php#77638 (var_export'ing certain class
    instances segfaults). (cmb)

  - Fixed bug php#78840 (imploding $GLOBALS crashes). (cmb)

  - Fixed bug php#78833 (Integer overflow in pack causes
    out-of-bound access). (cmb)

  - Fixed bug php#78814 (strip_tags allows / in tag name =>
    whitelist bypass). (cmb)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-437d94e271"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^30([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 30", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC30", reference:"php-7.3.13-1.fc30")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
