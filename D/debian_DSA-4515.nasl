#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4515. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128511);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/01");

  script_cve_id("CVE-2019-8644", "CVE-2019-8649", "CVE-2019-8658", "CVE-2019-8666", "CVE-2019-8669", "CVE-2019-8671", "CVE-2019-8672", "CVE-2019-8673", "CVE-2019-8676", "CVE-2019-8677", "CVE-2019-8678", "CVE-2019-8679", "CVE-2019-8680", "CVE-2019-8681", "CVE-2019-8683", "CVE-2019-8684", "CVE-2019-8686", "CVE-2019-8687", "CVE-2019-8688", "CVE-2019-8689", "CVE-2019-8690");
  script_xref(name:"DSA", value:"4515");

  script_name(english:"Debian DSA-4515-1 : webkit2gtk - security update");
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

  - CVE-2019-8644
    G. Geshev discovered memory corruption issues that can
    lead to arbitrary code execution.

  - CVE-2019-8649
    Sergei Glazunov discovered an issue that may lead to
    universal cross site scripting.

  - CVE-2019-8658
    akayn discovered an issue that may lead to universal
    cross site scripting.

  - CVE-2019-8666
    Zongming Wang and Zhe Jin discovered memory corruption
    issues that can lead to arbitrary code execution.

  - CVE-2019-8669
    akayn discovered memory corruption issues that can lead
    to arbitrary code execution.

  - CVE-2019-8671
    Apple discovered memory corruption issues that can lead
    to arbitrary code execution.

  - CVE-2019-8672
    Samuel Gross discovered memory corruption issues that
    can lead to arbitrary code execution.

  - CVE-2019-8673
    Soyeon Park and Wen Xu discovered memory corruption
    issues that can lead to arbitrary code execution.

  - CVE-2019-8676
    Soyeon Park and Wen Xu discovered memory corruption
    issues that can lead to arbitrary code execution.

  - CVE-2019-8677
    Jihui Lu discovered memory corruption issues that can
    lead to arbitrary code execution.

  - CVE-2019-8678
    An anonymous researcher, Anthony Lai, Ken Wong,
    Jeonghoon Shin, Johnny Yu, Chris Chan, Phil Mok, Alan
    Ho, and Byron Wai discovered memory corruption issues
    that can lead to arbitrary code execution.

  - CVE-2019-8679
    Jihui Lu discovered memory corruption issues that can
    lead to arbitrary code execution.

  - CVE-2019-8680
    Jihui Lu discovered memory corruption issues that can
    lead to arbitrary code execution.

  - CVE-2019-8681
    G. Geshev discovered memory corruption issues that can
    lead to arbitrary code execution.

  - CVE-2019-8683
    lokihardt discovered memory corruption issues that can
    lead to arbitrary code execution.

  - CVE-2019-8684
    lokihardt discovered memory corruption issues that can
    lead to arbitrary code execution.

  - CVE-2019-8686
    G. Geshev discovered memory corruption issues that can
    lead to arbitrary code execution.

  - CVE-2019-8687
    Apple discovered memory corruption issues that can lead
    to arbitrary code execution.

  - CVE-2019-8688
    Insu Yun discovered memory corruption issues that can
    lead to arbitrary code execution.

  - CVE-2019-8689
    lokihardt discovered memory corruption issues that can
    lead to arbitrary code execution.

  - CVE-2019-8690
    Sergei Glazunov discovered an issue that may lead to
    universal cross site scripting.

You can see more details on the WebKitGTK and WPE WebKit Security
Advisory WSA-2019-0004."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8672"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8679"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-8690"
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
    value:"https://www.debian.org/security/2019/dsa-4515"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the webkit2gtk packages.

For the stable distribution (buster), these problems have been fixed
in version 2.24.4-1~deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:webkit2gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"gir1.2-javascriptcoregtk-4.0", reference:"2.24.4-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"gir1.2-webkit2-4.0", reference:"2.24.4-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libjavascriptcoregtk-4.0-18", reference:"2.24.4-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libjavascriptcoregtk-4.0-bin", reference:"2.24.4-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libjavascriptcoregtk-4.0-dev", reference:"2.24.4-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libwebkit2gtk-4.0-37", reference:"2.24.4-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libwebkit2gtk-4.0-37-gtk2", reference:"2.24.4-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libwebkit2gtk-4.0-dev", reference:"2.24.4-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libwebkit2gtk-4.0-doc", reference:"2.24.4-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"webkit2gtk-driver", reference:"2.24.4-1~deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
