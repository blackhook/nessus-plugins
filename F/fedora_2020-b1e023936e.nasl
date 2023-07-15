#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-b1e023936e.
#

include("compat.inc");

if (description)
{
  script_id(139709);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/24");

  script_cve_id("CVE-2020-16145");
  script_xref(name:"FEDORA", value:"2020-b1e023936e");

  script_name(english:"Fedora 31 : roundcubemail (2020-b1e023936e)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"**RELEASE 1.4.8**

  - **Security**: Fix potential XSS issue in HTML editor of
    the identity signature input (#7507)

  - Managesieve: Fix too-small input field in Elastic when
    using custom headers (#7498)

  - Fix support for an error as a string in
    message_before_send hook (#7475)

  - Elastic: Fix redundant scrollbar in plain text editor on
    mail reply (#7500)

  - Elastic: Fix deleted and replied+forwarded icons on
    messages list (#7503)

  - Managesieve: Allow angle brackets in out-of-office
    message body (#7518)

  - Fix bug in conversion of email addresses to mailto links
    in plain text messages (#7526)

  - Fix format=flowed formatting on plain text part derived
    from the HTML content (#7504)

  - Fix incorrect rewriting of internal links in HTML
    content (#7512)

  - Fix handling links without defined protocol (#7454)

  - Fix paging of search results on IMAP servers with no
    SORT capability (#7462)

  - Fix detecting special folders on servers with both
    SPECIAL-USE and LIST-STATUS (#7525)

  - **Security**: Fix cross-site scripting (XSS) via HTML
    messages with malicious svg content [CVE-2020-16145]

  - **Security**: Fix cross-site scripting (XSS) via HTML
    messages with malicious math content

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-b1e023936e"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected roundcubemail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:roundcubemail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:31");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/20");
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
if (rpm_check(release:"FC31", reference:"roundcubemail-1.4.8-1.fc31")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "roundcubemail");
}
