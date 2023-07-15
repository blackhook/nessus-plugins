#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-82.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(145398);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-1971", "CVE-2020-8265", "CVE-2020-8287");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"openSUSE Security Update : nodejs10 (openSUSE-2021-82)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for nodejs10 fixes the following issues :

  - New upstream LTS version 10.23.1 :

  - CVE-2020-8265: use-after-free in TLSWrap (High) bug in
    TLS implementation. When writing to a TLS enabled
    socket, node::StreamBase::Write calls
    node::TLSWrap::DoWrite with a freshly allocated
    WriteWrap object as first argument. If the DoWrite
    method does not return an error, this object is passed
    back to the caller as part of a StreamWriteResult
    structure. This may be exploited to corrupt memory
    leading to a Denial of Service or potentially other
    exploits (bsc#1180553)

  - CVE-2020-8287: HTTP Request Smuggling allow two copies
    of a header field in a http request. For example, two
    Transfer-Encoding header fields. In this case Node.js
    identifies the first header field and ignores the
    second. This can lead to HTTP Request Smuggling
    (https://cwe.mitre.org/data/definitions/444.html).
    (bsc#1180554)

  - CVE-2020-1971: OpenSSL - EDIPARTYNAME NULL pointer
    de-reference (High) This is a vulnerability in OpenSSL
    which may be exploited through Node.js. (bsc#1179491)

  - New upstream LTS version 10.23.0 :

  - deps: upgrade npm to 6.14.8

  - n-api :

  + create N-API version 7

  + expose napi_build_version variable

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179491");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180553");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180554");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/444.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected nodejs10 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs10-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs10-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:npm10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"nodejs10-10.23.1-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nodejs10-debuginfo-10.23.1-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nodejs10-debugsource-10.23.1-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nodejs10-devel-10.23.1-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"npm10-10.23.1-lp151.2.15.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs10 / nodejs10-debuginfo / nodejs10-debugsource / etc");
}
