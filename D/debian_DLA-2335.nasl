#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2335-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139735);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/27");

  script_cve_id("CVE-2020-16287", "CVE-2020-16288", "CVE-2020-16289", "CVE-2020-16290", "CVE-2020-16291", "CVE-2020-16292", "CVE-2020-16293", "CVE-2020-16294", "CVE-2020-16295", "CVE-2020-16296", "CVE-2020-16297", "CVE-2020-16298", "CVE-2020-16299", "CVE-2020-16300", "CVE-2020-16301", "CVE-2020-16302", "CVE-2020-16303", "CVE-2020-16304", "CVE-2020-16305", "CVE-2020-16306", "CVE-2020-16307", "CVE-2020-16308", "CVE-2020-16309", "CVE-2020-16310", "CVE-2020-17538");
  script_xref(name:"IAVB", value:"2020-B-0046-S");

  script_name(english:"Debian DLA-2335-1 : ghostscript security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple vulnerabilities were found in ghostscript, an interpreter for
the PostScript language and for PDF, allowing an attacker to escalate
privileges and cause denial of service via crafted PS/EPS/PDF files.

For Debian 9 stretch, these problems have been fixed in version
9.26a~dfsg-0+deb9u7.

We recommend that you upgrade your ghostscript packages.

For the detailed security status of ghostscript please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/ghostscript

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00032.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/ghostscript"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/ghostscript"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgs9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgs9-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"9.0", prefix:"ghostscript", reference:"9.26a~dfsg-0+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"ghostscript-dbg", reference:"9.26a~dfsg-0+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"ghostscript-doc", reference:"9.26a~dfsg-0+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"ghostscript-x", reference:"9.26a~dfsg-0+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"libgs-dev", reference:"9.26a~dfsg-0+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"libgs9", reference:"9.26a~dfsg-0+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"libgs9-common", reference:"9.26a~dfsg-0+deb9u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
