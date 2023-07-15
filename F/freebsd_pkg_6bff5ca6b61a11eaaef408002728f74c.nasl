#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2020 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include('compat.inc');

if (description)
{
  script_id(137792);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/20");

  script_cve_id("CVE-2020-8169", "CVE-2020-8177");
  script_xref(name:"IAVA", value:"2020-A-0291-S");

  script_name(english:"FreeBSD : curl -- multiple vulnerabilities (6bff5ca6-b61a-11ea-aef4-08002728f74c)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"curl security problems :

CVE-2020-8169: Partial password leak over DNS on HTTP redirect

libcurl can be tricked to prepend a part of the password to the host
name before it resolves it, potentially leaking the partial password
over the network and to the DNS server(s).

libcurl can be given a username and password for HTTP authentication
when requesting an HTTP resource - used for HTTP Authentication such
as Basic, Digest, NTLM and similar. The credentials are set, either
together with CURLOPT_USERPWD or separately with CURLOPT_USERNAME and
CURLOPT_PASSWORD. Important detail: these strings are given to libcurl
as plain C strings and they are not supposed to be URL encoded.

In addition, libcurl also allows the credentials to be set in the URL,
using the standard RFC 3986 format : http://user:password@host/path.
In this case, the name and password are URL encoded as that's how they
appear in URLs.

If the options are set, they override the credentials set in the URL.

Internally, this is handled by storing the credentials in the 'URL
object' so that there is only a single set of credentials stored
associated with this single URL.

When libcurl handles a relative redirect (as opposed to an absolute
URL redirect) for an HTTP transfer, the server is only sending a new
path to the client and that path is applied on to the existing URL.
That 'applying' of the relative path on top of an absolute URL is done
by libcurl first generating a full absolute URL out of all the
components it has, then it applies the redirect and finally it
deconstructs the URL again into its separate components.

This security vulnerability originates in the fact that curl did not
correctly URL encode the credential data when set using one of the
curl_easy_setopt options described above. This made curl generate a
badly formatted full URL when it would do a redirect and the final
re-parsing of the URL would then go bad and wrongly consider a part of
the password field to belong to the host name.

The wrong host name would then be used in a name resolve lookup,
potentially leaking the host name + partial password in clear text
over the network (if plain DNS was used) and in particular to the used
DNS server(s).

CVE-2020-8177: curl overwrite local file with -J

curl can be tricked by a malicious server to overwrite a local file
when using -J (--remote-header-name) and -i (--include) in the same
command line.

The command line tool offers the -J option that saves a remote file
using the file name present in the Content-Disposition : response
header. curl then refuses to overwrite an existing local file using
the same name, if one already exists in the current directory.

The -J flag is designed to save a response body, and so it doesn't
work together with -i and there's logic that forbids it. However, the
check is flawed and doesn't properly check for when the options are
used in the reversed order: first using -J and then -i were mistakenly
accepted.

The result of this mistake was that incoming HTTP headers could
overwrite a local file if one existed, as the check to avoid the local
file was done first when body data was received, and due to the
mistake mentioned above, it could already have received and saved
headers by that time.

The saved file would only get response headers added to it, as it
would abort the saving when the first body byte arrives. A malicious
server could however still be made to send back virtually anything as
headers and curl would save them like this, until the first CRLF-CRLF
sequence appears.

(Also note that -J needs to be used in combination with -O to have any
effect.)");
  script_set_attribute(attribute:"see_also", value:"https://curl.haxx.se/docs/security.html");
  script_set_attribute(attribute:"see_also", value:"https://curl.haxx.se/docs/CVE-2020-8169.html");
  script_set_attribute(attribute:"see_also", value:"https://curl.haxx.se/docs/CVE-2020-8177.html");
  # https://vuxml.freebsd.org/freebsd/6bff5ca6-b61a-11ea-aef4-08002728f74c.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3af36dd0");
  script_set_attribute(attribute:"solution", value:
"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8169");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-8177");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"curl>=7.20.0<7.71.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
