#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(141734);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2015-9251", "CVE-2016-10735", "CVE-2018-14040", "CVE-2018-14042", "CVE-2018-20676", "CVE-2018-20677", "CVE-2019-11358", "CVE-2019-8331", "CVE-2020-11022", "CVE-2020-1722");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Scientific Linux Security Update : ipa on SL7.x x86_64 (20201001)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Security Fix(es) :

  - js-jquery: Cross-site scripting via cross-domain ajax
    requests (CVE-2015-9251)

  - bootstrap: XSS in the data-target attribute
    (CVE-2016-10735)

  - bootstrap: Cross-site Scripting (XSS) in the collapse
    data-parent attribute (CVE-2018-14040)

  - bootstrap: Cross-site Scripting (XSS) in the
    data-container property of tooltip. (CVE-2018-14042)

  - bootstrap: XSS in the tooltip data-viewport attribute
    (CVE-2018-20676)

  - bootstrap: XSS in the affix configuration target
    property (CVE-2018-20677)

  - bootstrap: XSS in the tooltip or popover data-template
    attribute (CVE-2019-8331)

  - js-jquery: prototype pollution in object's prototype
    leading to denial of service or remote code execution or
    property injection (CVE-2019-11358)

  - jquery: Cross-site scripting due to improper
    injQuery.htmlPrefilter method (CVE-2020-11022)

  - ipa: No password length restriction leads to denial of
    service (CVE-2020-1722)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind2010&L=SCIENTIFIC-LINUX-ERRATA&P=25987
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dce39327"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11022");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-python-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python2-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python2-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python2-ipaserver");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-client-4.6.8-5.el7")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-client-common-4.6.8-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-client-common-4.6.8-5.el7")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-common-4.6.8-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-common-4.6.8-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-debuginfo-4.6.8-5.el7")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-python-compat-4.6.8-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-python-compat-4.6.8-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-4.6.8-5.el7")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-server-common-4.6.8-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-common-4.6.8-5.el7")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-server-dns-4.6.8-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-dns-4.6.8-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-trust-ad-4.6.8-5.el7")) flag++;
if (rpm_check(release:"SL7", reference:"python2-ipaclient-4.6.8-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python2-ipaclient-4.6.8-5.el7")) flag++;
if (rpm_check(release:"SL7", reference:"python2-ipalib-4.6.8-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python2-ipalib-4.6.8-5.el7")) flag++;
if (rpm_check(release:"SL7", reference:"python2-ipaserver-4.6.8-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python2-ipaserver-4.6.8-5.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipa-client / ipa-client-common / ipa-common / ipa-debuginfo / etc");
}
