#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-677-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(36611);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2008-2237", "CVE-2008-2238", "CVE-2008-4937");
  script_bugtraq_id(31962);
  script_xref(name:"USN", value:"677-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.10 / 8.04 LTS / 8.10 : openoffice.org, openoffice.org-amd64 vulnerabilities (USN-677-1)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple memory overflow flaws were discovered in OpenOffice.org's
handling of WMF and EMF files. If a user were tricked into opening a
specially crafted document, a remote attacker might be able to execute
arbitrary code with user privileges. (CVE-2008-2237, CVE-2008-2238)

Dmitry E. Oboukhov discovered that senddoc, as included in
OpenOffice.org, created temporary files in an insecure way. Local
users could exploit a race condition to create or overwrite files with
the privileges of the user invoking the program. This issue only
affected Ubuntu 8.04 LTS. (CVE-2008-4937).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/677-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(59, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:broffice.org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cli-uno-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmythes-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuno-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuno-cli-basetypes1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuno-cli-cppuhelper1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuno-cli-types1.1-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuno-cli-ure1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-openoffice.org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-base-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-dev-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-dtd-officedocument1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-filter-binfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-filter-mobiledev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-filter-so52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-gcj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-gtk-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-java-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-en-us");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-za");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-ogltrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-presentation-minimizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-qa-api-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-qa-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-report-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-report-builder-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-sdbc-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-style-andromeda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-style-crystal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-style-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-style-hicontrast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-style-human");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-style-industrial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-style-tango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-uno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ttf-opensymbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ure-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2019 Canonical, Inc. / NASL script (C) 2009-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! ereg(pattern:"^(6\.06|7\.10|8\.04|8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.10 / 8.04 / 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libmythes-dev", pkgver:"2.0.2-2ubuntu12.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org", pkgver:"2.0.2-2ubuntu12.7-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-base", pkgver:"2.0.2-2ubuntu12.7-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-calc", pkgver:"2.0.2-2ubuntu12.7-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-common", pkgver:"2.0.2-2ubuntu12.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-core", pkgver:"2.0.2-2ubuntu12.7-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-dev", pkgver:"2.0.2-2ubuntu12.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-dev-doc", pkgver:"2.0.2-2ubuntu12.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-draw", pkgver:"2.0.2-2ubuntu12.7-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-evolution", pkgver:"2.0.2-2ubuntu12.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-filter-so52", pkgver:"2.0.2-2ubuntu12.7-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-gcj", pkgver:"2.0.2-2ubuntu12.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-gnome", pkgver:"2.0.2-2ubuntu12.7-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-gtk", pkgver:"2.0.2-2ubuntu12.7-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-gtk-gnome", pkgver:"2.0.2-2ubuntu12.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-impress", pkgver:"2.0.2-2ubuntu12.7-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-java-common", pkgver:"2.0.2-2ubuntu12.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-kde", pkgver:"2.0.2-2ubuntu12.7-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-l10n-en-us", pkgver:"2.0.2-2ubuntu12.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-math", pkgver:"2.0.2-2ubuntu12.7-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-officebean", pkgver:"2.0.2-2ubuntu12.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-qa-api-tests", pkgver:"2.0.2-2ubuntu12.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-qa-tools", pkgver:"2.0.2-2ubuntu12.7-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-writer", pkgver:"2.0.2-2ubuntu12.7-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2", pkgver:"2.0.2-2ubuntu12.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-base", pkgver:"2.0.2-2ubuntu12.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-calc", pkgver:"2.0.2-2ubuntu12.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-draw", pkgver:"2.0.2-2ubuntu12.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-evolution", pkgver:"2.0.2-2ubuntu12.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-gnome", pkgver:"2.0.2-2ubuntu12.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-impress", pkgver:"2.0.2-2ubuntu12.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-kde", pkgver:"2.0.2-2ubuntu12.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-math", pkgver:"2.0.2-2ubuntu12.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-writer", pkgver:"2.0.2-2ubuntu12.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python-uno", pkgver:"2.0.2-2ubuntu12.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ttf-opensymbol", pkgver:"2.0.2-2ubuntu12.7")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"broffice.org", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libmythes-dev", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libuno-cil", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"mozilla-openoffice.org", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-base", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-calc", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-common", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-core", pkgver:"1:2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-dev", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-dev-doc", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-draw", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-dtd-officedocument1.0", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-evolution", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-filter-binfilter", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-filter-mobiledev", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-gnome", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-gtk", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-headless", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-impress", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-java-common", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-kde", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-l10n-en-us", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-l10n-in", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-l10n-za", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-math", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-officebean", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-qa-api-tests", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-qa-tools", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-report-builder", pkgver:"1.0.0+OOo2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-sdbc-postgresql", pkgver:"0.7.5+OOo2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-style-andromeda", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-style-crystal", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-style-default", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-style-hicontrast", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-style-human", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-style-industrial", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-style-tango", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openoffice.org-writer", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"python-uno", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ttf-opensymbol", pkgver:"2.3.0-1ubuntu5.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"broffice.org", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmythes-dev", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libuno-cil", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mozilla-openoffice.org", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-base", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-base-core", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-calc", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-common", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-core", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-dev", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-dev-doc", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-draw", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-dtd-officedocument1.0", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-evolution", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-filter-binfilter", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-filter-mobiledev", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-gcj", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-gnome", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-gtk", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-headless", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-impress", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-java-common", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-kde", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-in", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-za", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-math", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-officebean", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-ogltrans", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-presentation-minimizer", pkgver:"1.0+OOo2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-qa-api-tests", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-qa-tools", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-report-builder", pkgver:"1.0.2+OOo2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-sdbc-postgresql", pkgver:"0.7.5+OOo2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-style-andromeda", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-style-crystal", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-style-hicontrast", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-style-human", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-style-industrial", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-style-tango", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-writer", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-uno", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ttf-opensymbol", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ure", pkgver:"1.4+OOo2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ure-dbg", pkgver:"1.4+OOo2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"broffice.org", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cli-uno-bridge", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmythes-dev", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libuno-cli-basetypes1.0-cil", pkgver:"1.0.10.0+OOo2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libuno-cli-cppuhelper1.0-cil", pkgver:"1.0.13.0+OOo2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libuno-cli-types1.1-cil", pkgver:"1.1.13.0+OOo2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libuno-cli-ure1.0-cil", pkgver:"1.0.13.0+OOo2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mozilla-openoffice.org", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-base", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-base-core", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-calc", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-common", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-core", pkgver:"1:2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-dev", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-dev-doc", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-draw", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-dtd-officedocument1.0", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-emailmerge", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-evolution", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-filter-binfilter", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-filter-mobiledev", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-gcj", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-gnome", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-gtk", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-headless", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-impress", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-java-common", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-kde", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-l10n-in", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-l10n-za", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-math", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-officebean", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-ogltrans", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-presentation-minimizer", pkgver:"1.0+OOo2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-qa-api-tests", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-qa-tools", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-report-builder", pkgver:"1.0.2+OOo2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-report-builder-bin", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-sdbc-postgresql", pkgver:"0.7.5+OOo2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-style-andromeda", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-style-crystal", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-style-hicontrast", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-style-human", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-style-industrial", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-style-tango", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openoffice.org-writer", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"python-uno", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ttf-opensymbol", pkgver:"2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ure", pkgver:"1.4+OOo2.4.1-11ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ure-dbg", pkgver:"1.4+OOo2.4.1-11ubuntu2.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "broffice.org / cli-uno-bridge / libmythes-dev / libuno-cil / etc");
}
