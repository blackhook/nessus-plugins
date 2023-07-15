#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-dfe1f0bac6.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120854);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2018-19518", "CVE-2018-19935");
  script_xref(name:"FEDORA", value:"2018-dfe1f0bac6");

  script_name(english:"Fedora 28 : php (2018-dfe1f0bac6)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**PHP version 7.2.13** (06 Dec 2018)

**ftp:**

  - Fixed bug php#77151 (ftp_close(): SSL_read on shutdown).
    (Remi)

**CLI:**

  - Fixed bug php#77111 (php-win.exe corrupts unicode
    symbols from cli parameters). (Anatol)

**Fileinfo:**

  - Fixed bug php#77095 (slowness regression in 7.2/7.3
    (compared to 7.1)). (Anatol)

**iconv:**

  - Fixed bug php#77147 (Fixing 60494 ignored
    ICONV_MIME_DECODE_CONTINUE_ON_ERROR). (cmb)

**Core:**

  - Fixed bug php#77231 (Segfault when using
    convert.quoted-printable-encode filter). (Stas)

**IMAP:**

  - Fixed bug php#77153 (imap_open allows to run arbitrary
    shell commands via mailbox parameter). (Stas)

**ODBC:**

  - Fixed bug php#77079 (odbc_fetch_object has incorrect
    type signature). (Jon Allen)

**Opcache:**

  - Fixed bug php#77058 (Type inference in opcache causes
    side effects). (Nikita)

  - Fixed bug php#77092 (array_diff_key() - segmentation
    fault). (Nikita)

**Phar:**

  - Fixed bug php#77022 (PharData always creates new files
    with mode 0666). (Stas)

  - Fixed bug php#77143 (Heap Buffer Overflow (READ: 4) in
    phar_parse_pharfile). (Stas)

**PGSQL:**

  - Fixed bug php#77047 (pg_convert has a broken regex for
    the 'TIME WITHOUT TIMEZONE' data type). (Andy Gajetzki)

**SOAP:**

  - Fixed bug php#50675 (SoapClient can't handle object
    references correctly). (Cameron Porter)

  - Fixed bug php#76348 (WSDL_CACHE_MEMORY causes
    Segmentation fault). (cmb)

  - Fixed bug php#77141 (Signedness issue in SOAP when
    precision=-1). (cmb)

**Sockets:**

  - Fixed bug php#67619 (Validate length on socket_write).
    (thiagooak)

----

**From upstream**

**IMAP**

  - Fix php#77020 NULL pointer dereference in imap_mail
    CVE-2018-19935

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-dfe1f0bac6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'php imap_open Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:28");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^28([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 28", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC28", reference:"php-7.2.13-2.fc28")) flag++;


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
