#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-8e36afc743.
#

include("compat.inc");

if (description)
{
  script_id(139680);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/25");

  script_cve_id("CVE-2020-7068");
  script_xref(name:"FEDORA", value:"2020-8e36afc743");
  script_xref(name:"IAVA", value:"2020-A-0373-S");

  script_name(english:"Fedora 31 : php (2020-8e36afc743)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"**PHP version 7.3.21** (06 Aug 2020)

**Apache:**

  - Fixed bug php#79030 (Upgrade apache2handler's
    php_apache_sapi_get_request_time to return usec).
    (Herbert256)

**Core:**

  - Fixed bug php#79877 (getimagesize function silently
    truncates after a null byte) (cmb)

  - Fixed bug php#79778 (Assertion failure if dumping
    closure with unresolved static variable). (Nikita)

  - Fixed bug php#79792 (HT iterators not removed if empty
    array is destroyed). (Nikita)

**Curl:**

  - Fixed bug php#79741 (curl_setopt CURLOPT_POSTFIELDS
    asserts on object with declared properties). (Nikita)

**Fileinfo:**

  - Fixed bug php#79756 (finfo_file crash (FILEINFO_MIME)).
    (cmb)

**FTP:**

  - Fixed bug php#55857 (ftp_size on large files). (cmb)

**Mbstring:**

  - Fixed bug php#79787 (mb_strimwidth does not trim
    string). (XXiang)

**Phar:**

  - Fixed bug php#79797 (Use of freed hash key in the
    phar_parse_zipfile function). (**CVE-2020-7068**) (cmb)

**Standard:**

  - Fixed bug php#70362 (Can't copy() large 'data://' with
    open_basedir). (cmb)

  - Fixed bug php#79817 (str_replace() does not handle
    INDIRECT elements). (Nikita)

  - Fixed bug php#78008 (dns_check_record() always return
    true on Alpine). (Andy Postnikov)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-8e36afc743"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7068");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:31");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/19");
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
if (rpm_check(release:"FC31", reference:"php-7.3.21-1.fc31")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
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
