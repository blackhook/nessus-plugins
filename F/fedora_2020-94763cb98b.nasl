#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-94763cb98b.
#

include("compat.inc");

if (description)
{
  script_id(141295);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/06");

  script_cve_id("CVE-2020-7069", "CVE-2020-7070");
  script_xref(name:"FEDORA", value:"2020-94763cb98b");
  script_xref(name:"IAVA", value:"2020-A-0445-S");

  script_name(english:"Fedora 31 : php (2020-94763cb98b)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"**PHP version 7.3.23** (01 Oct 2020)

**Core:**

  - Fixed bug php#80048 (Bug php#69100 has not been fixed
    for Windows). (cmb)

  - Fixed bug php#80049 (Memleak when coercing integers to
    string via variadic argument). (Nikita)

  - Fixed bug php#79699 (PHP parses encoded cookie names so
    malicious `__Host-` cookies can be sent).
    (**CVE-2020-7070**) (Stas)

**Calendar:**

  - Fixed bug php#80007 (Potential type confusion in
    unixtojd() parameter parsing). (Andy Postnikov)

**OPcache:**

  - Fixed bug php#80002 (calc free space for new interned
    string is wrong). (t-matsuno)

  - Fixed bug php#79825 (opcache.file_cache causes SIGSEGV
    when custom opcode handlers changed). (SammyK)

**OpenSSL:**

  - Fixed bug php#79601 (Wrong ciphertext/tag in AES-CCM
    encryption for a 12 bytes IV). (**CVE-2020-7069**)
    (Jakub Zelenka)

**PDO:**

  - Fixed bug php#80027 (Terrible performance using
    $query->fetch on queries with many bind parameters
    (Matteo)

**Standard:**

  - Fixed bug php#79986 (str_ireplace bug with diacritics
    characters). (cmb)

  - Fixed bug php#80077 (getmxrr test bug). (Rainer Jung)

  - Fixed bug php#72941 (Modifying bucket->data by-ref has
    no effect any longer). (cmb)

  - Fixed bug php#80067 (Omitting the port in bindto setting
    errors). (cmb)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-94763cb98b");
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:31");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^31([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 31", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC31", reference:"php-7.3.23-1.fc31")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
