#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4558. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130524);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/14");

  script_cve_id("CVE-2019-8625", "CVE-2019-8720", "CVE-2019-8769", "CVE-2019-8771");
  script_xref(name:"DSA", value:"4558");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"Debian DSA-4558-1 : webkit2gtk - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been discovered in the webkit2gtk web
engine :

  - CVE-2019-8625
    Sergei Glazunov discovered that maliciously crafted web
    content may lead to universal cross site scripting.

  - CVE-2019-8720
    Wen Xu discovered that maliciously crafted web content
    may lead to arbitrary code execution.

  - CVE-2019-8769
    Pierre Reimertz discovered that visiting a maliciously
    crafted website may reveal browsing history.

  - CVE-2019-8771
    Eliya Stein discovered that maliciously crafted web
    content may violate iframe sandboxing policy."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/webkit2gtk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/webkit2gtk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4558"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the webkit2gtk packages.

For the stable distribution (buster), these problems have been fixed
in version 2.26.1-3~deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8771");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:webkit2gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"gir1.2-javascriptcoregtk-4.0", reference:"2.26.1-3~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"gir1.2-webkit2-4.0", reference:"2.26.1-3~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libjavascriptcoregtk-4.0-18", reference:"2.26.1-3~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libjavascriptcoregtk-4.0-bin", reference:"2.26.1-3~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libjavascriptcoregtk-4.0-dev", reference:"2.26.1-3~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libwebkit2gtk-4.0-37", reference:"2.26.1-3~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libwebkit2gtk-4.0-37-gtk2", reference:"2.26.1-3~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libwebkit2gtk-4.0-dev", reference:"2.26.1-3~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libwebkit2gtk-4.0-doc", reference:"2.26.1-3~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"webkit2gtk-driver", reference:"2.26.1-3~deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
