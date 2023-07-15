#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4335. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118840);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/14");

  script_cve_id("CVE-2018-16843", "CVE-2018-16844", "CVE-2018-16845");
  script_xref(name:"DSA", value:"4335");

  script_name(english:"Debian DSA-4335-1 : nginx - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Three vulnerabilities were discovered in Nginx, a high-performance web
and reverse proxy server, which could result in denial of service in
processing HTTP/2 (via excessive memory/CPU usage) or server memory
disclosure in the ngx_http_mp4_module module (used for server-side MP4
streaming)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/nginx"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/nginx"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4335"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the nginx packages.

For the stable distribution (stretch), these problems have been fixed
in version 1.10.3-1+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16845");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-auth-pam", reference:"1.10.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-cache-purge", reference:"1.10.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-dav-ext", reference:"1.10.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-echo", reference:"1.10.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-fancyindex", reference:"1.10.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-geoip", reference:"1.10.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-headers-more-filter", reference:"1.10.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-image-filter", reference:"1.10.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-lua", reference:"1.10.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-ndk", reference:"1.10.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-perl", reference:"1.10.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-subs-filter", reference:"1.10.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-uploadprogress", reference:"1.10.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-upstream-fair", reference:"1.10.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-http-xslt-filter", reference:"1.10.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-mail", reference:"1.10.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-nchan", reference:"1.10.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libnginx-mod-stream", reference:"1.10.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"nginx", reference:"1.10.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"nginx-common", reference:"1.10.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"nginx-doc", reference:"1.10.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"nginx-extras", reference:"1.10.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"nginx-full", reference:"1.10.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"nginx-light", reference:"1.10.3-1+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
