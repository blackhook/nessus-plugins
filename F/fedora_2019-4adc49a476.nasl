#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-4adc49a476.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(130411);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2019-11043");
  script_xref(name:"FEDORA", value:"2019-4adc49a476");
  script_xref(name:"IAVA", value:"2019-A-0399-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0695");

  script_name(english:"Fedora 31 : php (2019-4adc49a476)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"**PHP version 7.3.11** (24 Oct 2019)

**Core:**

  - Fixed bug php#78535 (auto_detect_line_endings value not
    parsed as bool). (bugreportuser)

  - Fixed bug php#78620 (Out of memory error). (cmb, Nikita)

**Exif :**

  - Fixed bug php#78442 ('Illegal component' on
    exif_read_data since PHP7) (Kalle)

**FPM:**

  - Fixed bug php#78599 (env_path_info underflow in
    fpm_main.c can lead to RCE). (**CVE-2019-11043**) (Jakub
    Zelenka)

  - Fixed bug php#78413 (request_terminate_timeout does not
    take effect after fastcgi_finish_request). (Sergei
    Turchanov)

**MBString:**

  - Fixed bug php#78579 (mb_decode_numericentity: args
    number inconsistency). (cmb)

  - Fixed bug php#78609 (mb_check_encoding() no longer
    supports stringable objects). (cmb)

**MySQLi:**

  - Fixed bug php#76809 (SSL settings aren't respected when
    persistent connections are used). (fabiomsouto)

**Mysqlnd:**

  - Fixed bug php#78525 (Memory leak in pdo when reusing
    native prepared statements). (Nikita)

**PCRE:**

  - Fixed bug php#78272 (calling preg_match() before
    pcntl_fork() will freeze child process). (Nikita)

**PDO_MySQL:**

  - Fixed bug php#78623 (Regression caused by 'SP call
    yields additional empty result set'). (cmb)

**Session:**

  - Fixed bug php#78624 (session_gc return value for user
    defined session handlers). (bshaffer)

**Standard:**

  - Fixed bug php#76342 (file_get_contents waits twice
    specified timeout). (Thomas Calvet)

  - Fixed bug php#78612 (strtr leaks memory when integer
    keys are used and the subject string shorter). (Nikita)

  - Fixed bug php#76859 (stream_get_line skips data if used
    with data-generating filter). (kkopachev)

**Zip:**

  - Fixed bug php#78641 (addGlob can modify given
    remove_path value). (cmb)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-4adc49a476"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11043");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP-FPM Underflow RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:31");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"FC31", reference:"php-7.3.11-1.fc31")) flag++;


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
