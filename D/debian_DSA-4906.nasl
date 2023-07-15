#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4906. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(149082);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/30");

  script_cve_id("CVE-2021-21201", "CVE-2021-21202", "CVE-2021-21203", "CVE-2021-21204", "CVE-2021-21205", "CVE-2021-21207", "CVE-2021-21208", "CVE-2021-21209", "CVE-2021-21210", "CVE-2021-21211", "CVE-2021-21212", "CVE-2021-21213", "CVE-2021-21214", "CVE-2021-21215", "CVE-2021-21216", "CVE-2021-21217", "CVE-2021-21218", "CVE-2021-21219", "CVE-2021-21221", "CVE-2021-21222", "CVE-2021-21223", "CVE-2021-21224", "CVE-2021-21225", "CVE-2021-21226");
  script_xref(name:"DSA", value:"4906");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"Debian DSA-4906-1 : chromium - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been discovered in the chromium web
browser.

  - CVE-2021-21201
    Gengming Liu and Jianyu Chen discovered a use-after-free
    issue.

  - CVE-2021-21202
    David Erceg discovered a use-after-free issue in
    extensions.

  - CVE-2021-21203
    asnine discovered a use-after-free issue in
    Blink/Webkit.

  - CVE-2021-21204
    Tsai-Simek, Jeanette Ulloa, and Emily Voigtlander
    discovered a use-after-free issue in Blink/Webkit.

  - CVE-2021-21205
    Alison Huffman discovered a policy enforcement error.

  - CVE-2021-21207
    koocola and Nan Wang discovered a use-after-free in the
    indexed database.

  - CVE-2021-21208
    Ahmed Elsobky discovered a data validation error in the
    QR code scanner.

  - CVE-2021-21209
    Tom Van Goethem discovered an implementation error in
    the Storage API.

  - CVE-2021-21210
    @bananabr discovered an error in the networking
    implementation.

  - CVE-2021-21211
    Akash Labade discovered an error in the navigation
    implementation.

  - CVE-2021-21212
    Hugo Hue and Sze Yui Chau discovered an error in the
    network configuration user interface.

  - CVE-2021-21213
    raven discovered a use-after-free issue in the WebMIDI
    implementation.

  - CVE-2021-21214
    A use-after-free issue was discovered in the networking
    implementation.

  - CVE-2021-21215
    Abdulrahman Alqabandi discovered an error in the
    Autofill feature.

  - CVE-2021-21216
    Abdulrahman Alqabandi discovered an error in the
    Autofill feature.

  - CVE-2021-21217
    Zhou Aiting discovered use of uninitialized memory in
    the pdfium library.

  - CVE-2021-21218
    Zhou Aiting discovered use of uninitialized memory in
    the pdfium library.

  - CVE-2021-21219
    Zhou Aiting discovered use of uninitialized memory in
    the pdfium library.

  - CVE-2021-21221
    Guang Gong discovered insufficient validation of
    untrusted input.

  - CVE-2021-21222
    Guang Gong discovered a buffer overflow issue in the v8
    JavaScript library.

  - CVE-2021-21223
    Guang Gong discovered an integer overflow issue.

  - CVE-2021-21224
    Jose Martinez discovered a type error in the v8
    JavaScript library.

  - CVE-2021-21225
    Brendon Tiszka discovered an out-of-bounds memory access
    issue in the v8 JavaScript library.

  - CVE-2021-21226
    Brendon Tiszka discovered a use-after-free issue in the
    networking implementation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21203"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21208"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21216"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21217"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21222"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21225"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/chromium"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/chromium"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2021/dsa-4906"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the chromium packages.

For the stable distribution (buster), these problems have been fixed
in version 90.0.4430.85-1~deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"chromium", reference:"90.0.4430.85-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-common", reference:"90.0.4430.85-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-driver", reference:"90.0.4430.85-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-l10n", reference:"90.0.4430.85-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-sandbox", reference:"90.0.4430.85-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-shell", reference:"90.0.4430.85-1~deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
