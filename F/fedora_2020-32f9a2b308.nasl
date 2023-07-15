#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-32f9a2b308.
#

include("compat.inc");

if (description)
{
  script_id(134132);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/06");

  script_cve_id("CVE-2020-7061", "CVE-2020-7062", "CVE-2020-7063");
  script_xref(name:"FEDORA", value:"2020-32f9a2b308");

  script_name(english:"Fedora 31 : php (2020-32f9a2b308)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**PHP version 7.3.15** (20 Feb 2020)

**Core:**

  - Fixed bug php#71876 (Memory corruption
    htmlspecialchars(): charset `*' not supported). (Nikita)

  - Fixed bug #php#79146 (cscript can fail to run on some
    systems). (clarodeus)

  - Fixed bug php#78323 (Code 0 is returned on invalid
    options). (Ivan Mikheykin)

  - Fixed bug php#76047 (Use-after-free when accessing
    already destructed backtrace arguments). (Nikita)

**CURL:**

  - Fixed bug php#79078 (Hypothetical use-after-free in
    curl_multi_add_handle()). (cmb)

**Intl:**

  - Fixed bug php#79212 (NumberFormatter::format() may
    detect wrong type). (cmb)

**Libxml:**

  - Fixed bug php#79191 (Error in SoapClient ctor disables
    DOMDocument::save()). (Nikita, cmb)

**MBString:**

  - Fixed bug php#79154 (mb_convert_encoding() can modify
    $from_encoding). (cmb)

**MySQLnd:**

  - Fixed bug php#79084 (mysqlnd may fetch wrong column
    indexes with MYSQLI_BOTH). (cmb)

**OpenSSL:**

  - Fixed bug php#79145 (openssl memory leak). (cmb, Nikita)

**Phar:**

  - Fixed bug php#79082 (Files added to tar with
    Phar::buildFromIterator have all-access permissions).
    (**CVE-2020-7063**) (stas)

  - Fixed bug php#79171 (heap-buffer-overflow in
    phar_extract_file). (**CVE-2020-7061**) (cmb)

  - Fixed bug php#76584 (PharFileInfo::decompress not
    working). (cmb)

**Reflection:**

  - Fixed bug php#79115 (ReflectionClass::isCloneable call
    reflected class __destruct). (Nikita)

**Session:**

  - Fixed bug php#79221 (NULL pointer Dereference in PHP
    Session Upload Progress). (**CVE-2020-7062**) (stas)

**SPL:**

  - Fixed bug php#79151 (heap use after free caused by
    spl_dllist_it_helper_move_forward). (Nikita)

**Standard:**

  - Fixed bug php#78902 (Memory leak when using
    stream_filter_append). (liudaixiao)

**Testing:**

  - Fixed bug php#78090 (bug45161.phpt takes forever to
    finish). (cmb)

**XSL:**

  - Fixed bug php#70078 (XSL callbacks with nodes as
    parameter leak memory). (cmb)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-32f9a2b308"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:31");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/28");
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
if (! preg(pattern:"^31([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 31", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC31", reference:"php-7.3.15-1.fc31")) flag++;


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
