#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4881. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(148277);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-8169", "CVE-2020-8177", "CVE-2020-8231", "CVE-2020-8284", "CVE-2020-8285", "CVE-2020-8286", "CVE-2021-22876", "CVE-2021-22890");
  script_xref(name:"DSA", value:"4881");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Debian DSA-4881-1 : curl - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple vulnerabilities were discovered in cURL, an URL transfer
library :

  - CVE-2020-8169
    Marek Szlagor reported that libcurl could be tricked
    into prepending a part of the password to the host name
    before it resolves it, potentially leaking the partial
    password over the network and to the DNS server(s).

  - CVE-2020-8177
    sn reported that curl could be tricked by a malicious
    server into overwriting a local file when using the -J
    (--remote-header-name) and -i (--include) options in the
    same command line.

  - CVE-2020-8231
    Marc Aldorasi reported that libcurl might use the wrong
    connection when an application using libcurl's multi API
    sets the option CURLOPT_CONNECT_ONLY, which could lead
    to information leaks.

  - CVE-2020-8284
    Varnavas Papaioannou reported that a malicious server
    could use the PASV response to trick curl into
    connecting back to an arbitrary IP address and port,
    potentially making curl extract information about
    services that are otherwise private and not disclosed.

  - CVE-2020-8285
    xnynx reported that libcurl could run out of stack space
    when using the FTP wildcard matching functionality
    (CURLOPT_CHUNK_BGN_FUNCTION).

  - CVE-2020-8286
    It was reported that libcurl didn't verify that an OCSP
    response actually matches the certificate it is intended
    to.

  - CVE-2021-22876
    Viktor Szakats reported that libcurl does not strip off
    user credentials from the URL when automatically
    populating the Referer HTTP request header field in
    outgoing HTTP requests.

  - CVE-2021-22890
    Mingtao Yang reported that, when using an HTTPS proxy
    and TLS 1.3, libcurl could confuse session tickets
    arriving from the HTTPS proxy as if they arrived from
    the remote server instead. This could allow an HTTPS
    proxy to trick libcurl into using the wrong session
    ticket for the host and thereby circumvent the server
    TLS certificate check."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=965280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=965281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=968831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=977161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=977162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=977163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-8169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-8177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-8231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-8284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-8285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-8286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-22876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-22890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/curl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/curl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2021/dsa-4881"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the curl packages.

For the stable distribution (buster), these problems have been fixed
in version 7.64.0-4+deb10u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22876");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"curl", reference:"7.64.0-4+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libcurl3-gnutls", reference:"7.64.0-4+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libcurl3-nss", reference:"7.64.0-4+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libcurl4", reference:"7.64.0-4+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libcurl4-doc", reference:"7.64.0-4+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libcurl4-gnutls-dev", reference:"7.64.0-4+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libcurl4-nss-dev", reference:"7.64.0-4+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libcurl4-openssl-dev", reference:"7.64.0-4+deb10u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
