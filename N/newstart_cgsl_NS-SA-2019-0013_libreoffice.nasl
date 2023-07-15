#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0013. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127163);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2018-6871");

  script_name(english:"NewStart CGSL MAIN 5.04 : libreoffice Vulnerability (NS-SA-2019-0013)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 5.04, has libreoffice packages installed that are affected by a
vulnerability:

  - A flaw was found in libreoffice before 5.4.5 and before
    6.0.1. Arbitrary remote file disclosure may be achieved
    by the use of the WEBSERVICE formula in a specially
    crafted ODS file. (CVE-2018-6871)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0013");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL libreoffice packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6871");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 5.04": [
    "autocorr-af-5.0.6.2-15.el7_4",
    "autocorr-bg-5.0.6.2-15.el7_4",
    "autocorr-ca-5.0.6.2-15.el7_4",
    "autocorr-cs-5.0.6.2-15.el7_4",
    "autocorr-da-5.0.6.2-15.el7_4",
    "autocorr-de-5.0.6.2-15.el7_4",
    "autocorr-en-5.0.6.2-15.el7_4",
    "autocorr-es-5.0.6.2-15.el7_4",
    "autocorr-fa-5.0.6.2-15.el7_4",
    "autocorr-fi-5.0.6.2-15.el7_4",
    "autocorr-fr-5.0.6.2-15.el7_4",
    "autocorr-ga-5.0.6.2-15.el7_4",
    "autocorr-hr-5.0.6.2-15.el7_4",
    "autocorr-hu-5.0.6.2-15.el7_4",
    "autocorr-is-5.0.6.2-15.el7_4",
    "autocorr-it-5.0.6.2-15.el7_4",
    "autocorr-ja-5.0.6.2-15.el7_4",
    "autocorr-ko-5.0.6.2-15.el7_4",
    "autocorr-lb-5.0.6.2-15.el7_4",
    "autocorr-lt-5.0.6.2-15.el7_4",
    "autocorr-mn-5.0.6.2-15.el7_4",
    "autocorr-nl-5.0.6.2-15.el7_4",
    "autocorr-pl-5.0.6.2-15.el7_4",
    "autocorr-pt-5.0.6.2-15.el7_4",
    "autocorr-ro-5.0.6.2-15.el7_4",
    "autocorr-ru-5.0.6.2-15.el7_4",
    "autocorr-sk-5.0.6.2-15.el7_4",
    "autocorr-sl-5.0.6.2-15.el7_4",
    "autocorr-sr-5.0.6.2-15.el7_4",
    "autocorr-sv-5.0.6.2-15.el7_4",
    "autocorr-tr-5.0.6.2-15.el7_4",
    "autocorr-vi-5.0.6.2-15.el7_4",
    "autocorr-zh-5.0.6.2-15.el7_4",
    "libreoffice-5.0.6.2-15.el7_4",
    "libreoffice-base-5.0.6.2-15.el7_4",
    "libreoffice-bsh-5.0.6.2-15.el7_4",
    "libreoffice-calc-5.0.6.2-15.el7_4",
    "libreoffice-core-5.0.6.2-15.el7_4",
    "libreoffice-debuginfo-5.0.6.2-15.el7_4",
    "libreoffice-draw-5.0.6.2-15.el7_4",
    "libreoffice-emailmerge-5.0.6.2-15.el7_4",
    "libreoffice-filters-5.0.6.2-15.el7_4",
    "libreoffice-gdb-debug-support-5.0.6.2-15.el7_4",
    "libreoffice-glade-5.0.6.2-15.el7_4",
    "libreoffice-graphicfilter-5.0.6.2-15.el7_4",
    "libreoffice-impress-5.0.6.2-15.el7_4",
    "libreoffice-langpack-af-5.0.6.2-15.el7_4",
    "libreoffice-langpack-ar-5.0.6.2-15.el7_4",
    "libreoffice-langpack-as-5.0.6.2-15.el7_4",
    "libreoffice-langpack-bg-5.0.6.2-15.el7_4",
    "libreoffice-langpack-bn-5.0.6.2-15.el7_4",
    "libreoffice-langpack-br-5.0.6.2-15.el7_4",
    "libreoffice-langpack-ca-5.0.6.2-15.el7_4",
    "libreoffice-langpack-cs-5.0.6.2-15.el7_4",
    "libreoffice-langpack-cy-5.0.6.2-15.el7_4",
    "libreoffice-langpack-da-5.0.6.2-15.el7_4",
    "libreoffice-langpack-de-5.0.6.2-15.el7_4",
    "libreoffice-langpack-dz-5.0.6.2-15.el7_4",
    "libreoffice-langpack-el-5.0.6.2-15.el7_4",
    "libreoffice-langpack-en-5.0.6.2-15.el7_4",
    "libreoffice-langpack-es-5.0.6.2-15.el7_4",
    "libreoffice-langpack-et-5.0.6.2-15.el7_4",
    "libreoffice-langpack-eu-5.0.6.2-15.el7_4",
    "libreoffice-langpack-fa-5.0.6.2-15.el7_4",
    "libreoffice-langpack-fi-5.0.6.2-15.el7_4",
    "libreoffice-langpack-fr-5.0.6.2-15.el7_4",
    "libreoffice-langpack-ga-5.0.6.2-15.el7_4",
    "libreoffice-langpack-gl-5.0.6.2-15.el7_4",
    "libreoffice-langpack-gu-5.0.6.2-15.el7_4",
    "libreoffice-langpack-he-5.0.6.2-15.el7_4",
    "libreoffice-langpack-hi-5.0.6.2-15.el7_4",
    "libreoffice-langpack-hr-5.0.6.2-15.el7_4",
    "libreoffice-langpack-hu-5.0.6.2-15.el7_4",
    "libreoffice-langpack-it-5.0.6.2-15.el7_4",
    "libreoffice-langpack-ja-5.0.6.2-15.el7_4",
    "libreoffice-langpack-kk-5.0.6.2-15.el7_4",
    "libreoffice-langpack-kn-5.0.6.2-15.el7_4",
    "libreoffice-langpack-ko-5.0.6.2-15.el7_4",
    "libreoffice-langpack-lt-5.0.6.2-15.el7_4",
    "libreoffice-langpack-lv-5.0.6.2-15.el7_4",
    "libreoffice-langpack-mai-5.0.6.2-15.el7_4",
    "libreoffice-langpack-ml-5.0.6.2-15.el7_4",
    "libreoffice-langpack-mr-5.0.6.2-15.el7_4",
    "libreoffice-langpack-nb-5.0.6.2-15.el7_4",
    "libreoffice-langpack-nl-5.0.6.2-15.el7_4",
    "libreoffice-langpack-nn-5.0.6.2-15.el7_4",
    "libreoffice-langpack-nr-5.0.6.2-15.el7_4",
    "libreoffice-langpack-nso-5.0.6.2-15.el7_4",
    "libreoffice-langpack-or-5.0.6.2-15.el7_4",
    "libreoffice-langpack-pa-5.0.6.2-15.el7_4",
    "libreoffice-langpack-pl-5.0.6.2-15.el7_4",
    "libreoffice-langpack-pt-BR-5.0.6.2-15.el7_4",
    "libreoffice-langpack-pt-PT-5.0.6.2-15.el7_4",
    "libreoffice-langpack-ro-5.0.6.2-15.el7_4",
    "libreoffice-langpack-ru-5.0.6.2-15.el7_4",
    "libreoffice-langpack-si-5.0.6.2-15.el7_4",
    "libreoffice-langpack-sk-5.0.6.2-15.el7_4",
    "libreoffice-langpack-sl-5.0.6.2-15.el7_4",
    "libreoffice-langpack-sr-5.0.6.2-15.el7_4",
    "libreoffice-langpack-ss-5.0.6.2-15.el7_4",
    "libreoffice-langpack-st-5.0.6.2-15.el7_4",
    "libreoffice-langpack-sv-5.0.6.2-15.el7_4",
    "libreoffice-langpack-ta-5.0.6.2-15.el7_4",
    "libreoffice-langpack-te-5.0.6.2-15.el7_4",
    "libreoffice-langpack-th-5.0.6.2-15.el7_4",
    "libreoffice-langpack-tn-5.0.6.2-15.el7_4",
    "libreoffice-langpack-tr-5.0.6.2-15.el7_4",
    "libreoffice-langpack-ts-5.0.6.2-15.el7_4",
    "libreoffice-langpack-uk-5.0.6.2-15.el7_4",
    "libreoffice-langpack-ve-5.0.6.2-15.el7_4",
    "libreoffice-langpack-xh-5.0.6.2-15.el7_4",
    "libreoffice-langpack-zh-Hans-5.0.6.2-15.el7_4",
    "libreoffice-langpack-zh-Hant-5.0.6.2-15.el7_4",
    "libreoffice-langpack-zu-5.0.6.2-15.el7_4",
    "libreoffice-librelogo-5.0.6.2-15.el7_4",
    "libreoffice-math-5.0.6.2-15.el7_4",
    "libreoffice-nlpsolver-5.0.6.2-15.el7_4",
    "libreoffice-officebean-5.0.6.2-15.el7_4",
    "libreoffice-ogltrans-5.0.6.2-15.el7_4",
    "libreoffice-opensymbol-fonts-5.0.6.2-15.el7_4",
    "libreoffice-pdfimport-5.0.6.2-15.el7_4",
    "libreoffice-postgresql-5.0.6.2-15.el7_4",
    "libreoffice-pyuno-5.0.6.2-15.el7_4",
    "libreoffice-rhino-5.0.6.2-15.el7_4",
    "libreoffice-sdk-5.0.6.2-15.el7_4",
    "libreoffice-sdk-doc-5.0.6.2-15.el7_4",
    "libreoffice-ure-5.0.6.2-15.el7_4",
    "libreoffice-wiki-publisher-5.0.6.2-15.el7_4",
    "libreoffice-writer-5.0.6.2-15.el7_4",
    "libreoffice-xsltfilter-5.0.6.2-15.el7_4",
    "libreofficekit-5.0.6.2-15.el7_4",
    "libreofficekit-devel-5.0.6.2-15.el7_4"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libreoffice");
}
