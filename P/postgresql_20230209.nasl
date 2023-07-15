#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# Portions Copyright (C) 1996-2019, The PostgreSQL Global Development Group
# Portions Copyright (C) 1994, The Regents of the University of California
# Permission to use, copy, modify, and distribute this software and its documentation for any purpose, without fee, and without a written agreement is hereby granted, provided that the above copyright notice and this paragraph and the following two paragraphs appear in all copies.
# IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS" BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
##

include('compat.inc');

if (description)
{
  script_id(173964);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/19");

  script_cve_id("CVE-2022-41862");
  script_xref(name:"IAVB", value:"2023-B-0009-S");

  script_name(english:"PostgreSQL 12.x < 12.14 / 13.x < 13.10 / 14.x < 14.7 / 15.x < 15.2 Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is potentially affected by an information disclosure
vulnerability. In PostgreSQL, a modified, unauthenticated server can send an unterminated string during the
establishment of Kerberos transport encryption. In certain conditions a server can cause a libpq client to over-read
and report an error message containing uninitialized bytes.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.postgresql.org/about/news/postgresql-152-147-1310-1214-and-1119-released-2592/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d6274ab");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/support/security/CVE-2022-41862");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL 12.14 / 13.10 / 14.7 / 15.2 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41862");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_set_attribute(attribute:"stig_severity", value:"III");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("postgres_installed_windows.nbin", "postgres_installed_nix.nbin", "postgresql_version.nbin");
  script_require_ports("Services/postgresql", 5432, "installed_sw/PostgreSQL", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_postgresql.inc');

var app = 'PostgreSQL';
var win_local = TRUE;

if (!get_kb_item('SMB/Registry/Enumerated'))
  win_local = FALSE;

var port = get_service(svc:'postgresql', default:5432);
var kb_base = 'database/' + port + '/postgresql/';
var kb_ver = NULL;
var kb_path = kb_base + 'version';
var ver = get_kb_item(kb_path);
if (!empty_or_null(ver)) kb_ver = kb_path;

app_info = vcf::postgresql::get_app_info(app:app, port:port, kb_ver:kb_ver, kb_base:kb_base, win_local:win_local);
vcf::check_granularity(app_info:app_info, sig_segments:2);

#  12.14 / 13.10 / 14.7 / 15.2
var constraints = [
  { 'min_version' : '12.0', 'fixed_version' : '12.14' },
  { 'min_version' : '13.0', 'fixed_version' : '13.10' },
  { 'min_version' : '14.0', 'fixed_version' : '14.7' },
  { 'min_version' : '15.0', 'fixed_version' : '15.2' }
];

vcf::postgresql::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
