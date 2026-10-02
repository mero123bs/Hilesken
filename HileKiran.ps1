$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
# Yonetici kontrolu (bu surum kendini yukseltmez)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host 'HATA: Bu script YONETICI olarak calistirilmali. PowerShell/CMD i sag tik > Yonetici olarak calistir ile acip komutu tekrar yapistir.' -ForegroundColor Red
    return
}
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
try { $Host.UI.RawUI.WindowTitle = 'HileKiran' } catch {}
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue

# =====================================================================
# HileKiran - bu bilgisayardaki hile izlerini arar. Hicbir veri disari gonderilmez,
# hicbir dosya silinmez/degistirilmez. Sadece okur ve rapor yazar (process bellegi de sadece OKUNUR).
# =====================================================================

$script:Rep = New-Object System.Collections.Generic.List[string]
$script:F = New-Object System.Collections.Generic.List[object]
$script:Sys = New-Object System.Collections.Generic.List[object]
$script:UsnDel = @{}
$script:UsnRecent = New-Object System.Collections.Generic.List[object]
$script:BinItems = New-Object System.Collections.Generic.List[object]
$script:BinEmptied = @{}
$script:BinState = New-Object System.Collections.Generic.List[string]
$script:UsbList = New-Object System.Collections.Generic.List[object]
$script:GameDirs = New-Object System.Collections.Generic.List[string]
$script:ScanRoots = New-Object System.Collections.Generic.List[string]
$script:LogCand = New-Object System.Collections.Generic.List[object]
$script:ProfileJsonCand = New-Object System.Collections.Generic.List[object]
$script:JsonCand2 = New-Object System.Collections.Generic.List[object]
$script:JavaInfo = New-Object System.Collections.Generic.List[string]
$script:fileCount = 0
$script:HkOk = $false
$Started = Get-Date
$UP = $env:USERPROFILE

$Desktop = [Environment]::GetFolderPath('Desktop')
if (-not $Desktop) { $Desktop = $UP }
$ReportPath = Join-Path $Desktop 'HileKiran-rapor.txt'

function Log([string]$t, [string]$c = 'Gray', [bool]$fileOnly = $false) {
    if (-not $fileOnly) { Write-Host $t -ForegroundColor $c }
    [void]$script:Rep.Add($t)
}
function Step([string]$t) { Log '' 'Gray'; Log $t 'Cyan' }
function Fmt($d) {
    if ($d) { try { return ([datetime]$d).ToString('dd.MM.yyyy HH:mm:ss') } catch { return [string]$d } }
    return '-'
}
function Ft([long]$v) {
    if ($v -le 0) { return $null }
    try {
        $d = [datetime]::FromFileTime($v)
        if ($d.Year -lt 2000) { return $null }
        return $d
    } catch { return $null }
}

# ---------------- C# yardimcilari (registry zamani, sikistirma, pencere, surucu haritasi) ----------------
$cs = @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
public static class HkNative {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);
    public delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc p, IntPtr l);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr h, int i);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int RegQueryInfoKey(Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey, StringBuilder lpClass, IntPtr lpcbClass, IntPtr lpReserved, IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen, IntPtr lpcbMaxClassLen, IntPtr lpcValues, IntPtr lpcbMaxValueNameLen, IntPtr lpcbMaxValueLen, IntPtr lpcbSecurityDescriptor, out long lpftLastWriteTime);
    [DllImport("ntdll.dll")] public static extern uint RtlGetCompressionWorkSpaceSize(ushort fmt, out uint ws, out uint fw);
    [DllImport("ntdll.dll")] public static extern uint RtlDecompressBufferEx(ushort fmt, byte[] ub, uint ubs, byte[] cb, uint cbs, out uint fin, byte[] ws);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct FIND_STREAM_DATA { public long StreamSize; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)] public string StreamName; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr FindFirstStreamW(string f, int lvl, out FIND_STREAM_DATA d, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool FindNextStreamW(IntPtr h, out FIND_STREAM_DATA d);
    [DllImport("kernel32.dll")] static extern bool FindClose(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint acc, bool inh, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);
    [StructLayout(LayoutKind.Sequential)] public struct MBI { public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect; public IntPtr RegionSize; public uint State; public uint Protect; public uint Type; }
    [DllImport("kernel32.dll")] static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr a, out MBI m, IntPtr len);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr p, uint acc, out IntPtr tok);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool LookupPrivilegeValue(string sys, string name, out long luid);
    [StructLayout(LayoutKind.Sequential, Pack = 1)] struct TokPriv { public int Count; public long Luid; public int Attr; }
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool AdjustTokenPrivileges(IntPtr tok, bool dis, ref TokPriv np, int len, IntPtr prev, IntPtr ret);

    // NTFS ADS (alternate data stream) listesi: "ad|boyut"
    public static List<string> Streams(string path) {
        List<string> res = new List<string>();
        FIND_STREAM_DATA d;
        IntPtr h = FindFirstStreamW(path, 0, out d, 0);
        if (h == new IntPtr(-1)) return res;
        do { res.Add(d.StreamName + "|" + d.StreamSize.ToString()); } while (FindNextStreamW(h, out d));
        FindClose(h);
        return res;
    }
    // Process bellegini okumak icin SeDebugPrivilege (sadece okuma)
    public static bool EnableDebug() {
        IntPtr tok;
        if (!OpenProcessToken(GetCurrentProcess(), 0x28, out tok)) return false;
        long luid;
        if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid)) { CloseHandle(tok); return false; }
        TokPriv tp = new TokPriv();
        tp.Count = 1; tp.Luid = luid; tp.Attr = 2;
        bool ok = AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        CloseHandle(tok);
        return ok;
    }
    static bool PrintA(char c) { return c >= (char)0x20 && c < (char)0x7F; }
    static bool PrintU(char c) { return (c >= (char)0x20 && c < (char)0x7F) || (c >= (char)0xC0 && c <= (char)0x17F); }
    static void Harvest(string text, bool uni, Regex r, int minLen, Dictionary<string, bool> seen, List<string> res) {
        foreach (Match m in r.Matches(text)) {
            int a = m.Index;
            int lim = m.Index - 300; if (lim < 0) lim = 0;
            while (a > lim && (uni ? PrintU(text[a - 1]) : PrintA(text[a - 1]))) a--;
            int e = m.Index + m.Length;
            int lim2 = e + 200; if (lim2 > text.Length) lim2 = text.Length;
            while (e < lim2 && (uni ? PrintU(text[e]) : PrintA(text[e]))) e++;
            if (e - a < minLen) continue;
            string s = text.Substring(a, e - a);
            if (!seen.ContainsKey(s)) { seen[s] = true; res.Add(s); if (res.Count >= 150000) return; }
        }
    }
    // Bir process'in (Private/Mapped/Image) bellegindeki ASCII + UTF-16 stringleri tarar, rx ile eslesenleri dondurur. Sadece okur.
    public static List<string> MemStrings(int pid, string rx, int minLen, bool mapped, bool priv, bool image, long maxBytes) {
        IntPtr h = OpenProcess(0x0410, false, pid);
        if (h == IntPtr.Zero) h = OpenProcess(0x1010, false, pid);
        if (h == IntPtr.Zero) return null;
        List<string> res = new List<string>();
        Dictionary<string, bool> seen = new Dictionary<string, bool>();
        Regex r = new Regex(rx, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        Encoding lat = Encoding.GetEncoding(28591);
        byte[] buf = new byte[4 * 1024 * 1024];
        int mbiSize = Marshal.SizeOf(typeof(MBI));
        long addr = 0; long total = 0;
        while (total < maxBytes && res.Count < 150000) {
            MBI m;
            if (VirtualQueryEx(h, new IntPtr(addr), out m, new IntPtr(mbiSize)) == IntPtr.Zero) break;
            long size = m.RegionSize.ToInt64();
            long baseA = m.BaseAddress.ToInt64();
            if (size <= 0) break;
            bool ok = (m.State == 0x1000) && ((m.Protect & 0x101) == 0) && (m.Protect != 0);
            if (ok) {
                bool take = (m.Type == 0x20000 && priv) || (m.Type == 0x40000 && mapped) || (m.Type == 0x1000000 && image);
                if (take) {
                    long off = 0;
                    while (off < size && total < maxBytes) {
                        int cnt = (int)Math.Min((long)buf.Length, size - off);
                        IntPtr rd;
                        if (!ReadProcessMemory(h, new IntPtr(baseA + off), buf, new IntPtr(cnt), out rd)) break;
                        int n = rd.ToInt32();
                        if (n <= 0) break;
                        total += n;
                        Harvest(lat.GetString(buf, 0, n), false, r, minLen, seen, res);
                        if (n > 2) {
                            Harvest(Encoding.Unicode.GetString(buf, 0, n & ~1), true, r, minLen, seen, res);
                            Harvest(Encoding.Unicode.GetString(buf, 1, (n - 1) & ~1), true, r, minLen, seen, res);
                        }
                        if (off + n < size && n > 1024) off += n - 512; else off += n;
                    }
                }
            }
            addr = baseA + size;
            if (addr < 0) break;
        }
        CloseHandle(h);
        return res;
    }

    public static List<string> Overlays() {
        List<string> res = new List<string>();
        EnumWindows(delegate(IntPtr h, IntPtr l) {
            if (!IsWindowVisible(h)) return true;
            int ex = GetWindowLong(h, -20);
            bool layered = (ex & 0x80000) != 0;
            bool transp = (ex & 0x20) != 0;
            bool top = (ex & 0x8) != 0;
            if (layered && transp && top) {
                uint pid = 0;
                GetWindowThreadProcessId(h, out pid);
                StringBuilder sb = new StringBuilder(256);
                GetWindowText(h, sb, 256);
                RECT r;
                GetWindowRect(h, out r);
                res.Add(pid.ToString() + "|" + sb.ToString() + "|" + (r.Right - r.Left).ToString() + "x" + (r.Bottom - r.Top).ToString());
            }
            return true;
        }, IntPtr.Zero);
        return res;
    }
    public static byte[] Xpress(byte[] comp, uint usize) {
        uint ws = 0; uint fw = 0;
        if (RtlGetCompressionWorkSpaceSize(4, out ws, out fw) != 0) return null;
        byte[] work = new byte[ws];
        byte[] outb = new byte[usize];
        uint fin = 0;
        uint st = RtlDecompressBufferEx(4, outb, usize, comp, (uint)comp.Length, out fin, work);
        if (st != 0) return null;
        return outb;
    }
    public static long KeyTime(Microsoft.Win32.SafeHandles.SafeRegistryHandle h) {
        long ft = 0;
        int r = RegQueryInfoKey(h, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out ft);
        if (r != 0) return 0;
        return ft;
    }
}
'@
try {
    Add-Type -TypeDefinition $cs -Language CSharp -ErrorAction Stop
    $script:HkOk = $true
} catch { $script:HkOk = $false }

# ---------------- isim listeleri ----------------
$StrongNames = @(
    'wurst','aristois','meteor','mathax','doomsday','haruka','nursultan','dimosik','liquidbounce','minced','arbuz',
    'newcode','vanadium','catlean','nightware','wexside','mythra','oyvey','interia','iternia','inertia','catlavan',
    'zenora','vape','rusher','shoreline','slinky','augustus','boze','cutthrough','invmove','danqclient','baritone',
    'monoton','fdpclient','deadcode','radon','churka','koshka','litka','genclient','fluger','dettex','evaware',
    'moonproject','miraclous','nexgen','nightdlc','nextdlc','rogalik','ratka','spectra','shitpaste','wissend','amoral',
    'excellentomni','relake','deko','desteny','vredux','kimadlc','nixware','hachclient','neverlose','wiksi',
    'seasonreloadd','vegaline','voil','multiware','verist','foxclient','nurik','zovchik','hynix','zaharov','nuckerdlc',
    'nucker','komarudlc','komaru','waileent','astralisbeta','astralis','liorclient','mantance','lunoclient',
    'awesomeproject','zexis','wirent','hitdelay','hitsune','wingclient','aka_tweaks','potionrefill','visible-barriers',
    'jumpoverfences','attack_through_grass','pingbypass','astolfo','novoware','entrophy','zeroday','tenacity','hellion',
    'jigsaw','huzuni','7clicker','bape','cheatbreaker','goki','koid','cheatengine','extremeinjector','processhacker',
    'systeminformer','opautoclicker','gsautoclicker','tinytask','jitbit','phantomclient'
)
$WeakNames = @(
    'collapse','expensive','excellent','delta','grim','venus','arcade','zenith','essence','adjust','centric','future',
    'phantom','nix','moon','ares','wild','grace','damage','opal','dream','grape','reach','velocity','aimbot','esp','fly',
    'explicit','exclusive','flux','rise','sigma','thunder','impact','rocket','virgin','prestige','exhibition','ethereal',
    'preacher','deluxe','sparta','winner','kami','raven','ventura','argon','vapor','krypton','celestial'
)
function New-Rx([string[]]$names) {
    $sorted = $names | Sort-Object -Property { $_.Length } -Descending
    $alt = ($sorted | ForEach-Object { [regex]::Escape($_) }) -join '|'
    return New-Object System.Text.RegularExpressions.Regex ('(?i)(?<![a-z0-9])(' + $alt + ')(?![a-z0-9])')
}
$script:StrongRx = New-Rx $StrongNames
$script:WeakRx = New-Rx $WeakNames
$script:SubRx = New-Object System.Text.RegularExpressions.Regex ('(?i)(kill[ _\-]?aura|trigger[ _\-]?bot|aim[ _\-]?assist|aim[ _\-]?bot|auto[ _\-]?clicker|cheat[ _\-]?engine|elytra[ _\-]?target|jump[ _\-]?reset|scaffoldwalk|nofall|freecam|xray|antikb|autototem|autoarmor|chestesp|hitboxexpand)')
$script:BenignRx = '(?i)^(setup|install|installer|update|updater|unins\d*|uninstall|vc_?redist|vcredist|dxwebsetup|dotnet|windowsupdate|msedge|chrome|googleupdate|onedrive|teams|zoom|discord|spotify|steam|epicgames|riot|valorant|battle|nvidia|amd|radeon|intel|driver|java|jre|jdk|python|node|git|code|vscode|7z|winrar|vlc|obs|notepad|firefox|opera|brave|whatsapp|telegram|skype|anydesk|teamviewer|malwarebytes|avast|kaspersky|tlauncher|lunar|badlion|modrinth|prism|curseforge|overwolf|minecraft)'
$script:LauncherRx = '(?i)minecraft|launcher|lunar|badlion|modrinth|prism|multimc|feather|curseforge|tlauncher|labymod|salwyrr|atlauncher|technic|ftb|overwolf|ichor|sklauncher'
$IntExt = @('.exe','.dll','.jar','.zip','.rar','.7z','.bat','.cmd','.ps1','.vbs','.scr','.msi','.com')
$DisguiseExt = @('.png','.jpg','.jpeg','.gif','.bmp','.txt','.tmp','.dat','.bin','.log','.pdf','.mp3','.mp4','.wav','.ico','.db','.ttf','.cfg','.ini','.json','.xml','.lang','.mcmeta','.nbt')
$HeavyRx = '(?i)\\(node_modules|Cache|Code Cache|GPUCache|CacheStorage|Service Worker|IndexedDB|Local Storage|Session Storage|Crashpad|blob_storage|libraries|assets|runtime|\.git)(\\|$)'
$SigRx = '(?i)\\(Downloads|Desktop|Documents|Temp|Public)\\'

function Get-NameHit([string]$text, [bool]$weak = $true) {
    if ([string]::IsNullOrEmpty($text)) { return $null }
    $m = $script:SubRx.Match($text)
    if ($m.Success) { return [pscustomobject]@{ Name = $m.Groups[1].Value.ToLower(); Weak = $false } }
    $m = $script:StrongRx.Match($text)
    if ($m.Success) { return [pscustomobject]@{ Name = $m.Groups[1].Value.ToLower(); Weak = $false } }
    if ($weak) {
        $m = $script:WeakRx.Match($text)
        if ($m.Success) { return [pscustomobject]@{ Name = $m.Groups[1].Value.ToLower(); Weak = $true } }
    }
    return $null
}
function Name-Score($hit, [bool]$leaf) {
    if (-not $hit) { return 0 }
    if (-not $hit.Weak) { if ($leaf) { return 60 } else { return 40 } }
    if ($leaf) { return 25 }
    return 0
}

# ---------------- yardimci fonksiyonlar ----------------
$script:Drives = @()
foreach ($d in [IO.DriveInfo]::GetDrives()) { if ($d.IsReady) { $script:Drives += $d.Name.Substring(0, 2).ToUpper() } }
$script:VolMap = @{}
if ($script:HkOk) {
    foreach ($dl in $script:Drives) {
        $sb = New-Object System.Text.StringBuilder 512
        if ([HkNative]::QueryDosDevice($dl, $sb, 512) -gt 0) { $script:VolMap[$sb.ToString()] = $dl }
    }
}
$script:SerialMap = @{}
foreach ($ld in @(Get-CimInstance Win32_LogicalDisk)) {
    if ($ld.VolumeSerialNumber) { $script:SerialMap[$ld.VolumeSerialNumber.ToUpper()] = $ld.DeviceID.ToUpper() }
}
$script:FixedNtfs = @()
foreach ($d in [IO.DriveInfo]::GetDrives()) {
    if ($d.IsReady -and $d.DriveType -eq 'Fixed' -and $d.DriveFormat -eq 'NTFS') { $script:FixedNtfs += $d.Name.Substring(0, 2).ToUpper() }
}

function Get-Zone([string]$p) {
    if ($p -match '(?i)\\Users\\[^\\]+\\(Downloads|Desktop|Documents|Music|Videos|Pictures|OneDrive[^\\]*)\\') { return 'user' }
    if ($p -match '(?i)\\AppData\\Local\\Temp\\|\\Windows\\Temp\\|\\Temp\\') { return 'temp' }
    if ($p -match '(?i)\\AppData\\') { return 'appdata' }
    if ($p -match '(?i)\\Users\\Public\\|\\ProgramData\\') { return 'shared' }
    if ($p -match '(?i)^[A-Za-z]:\\Windows\\|\\Program Files( \(x86\))?\\|\\WindowsApps\\') { return 'system' }
    return 'other'
}
function Test-Signed([string]$p) {
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
        return ($s.Status -eq 'Valid')
    } catch { return $false }
}
function Get-ZoneInfo([string]$p) {
    try {
        $z = Get-Content -LiteralPath $p -Stream Zone.Identifier -ErrorAction Stop
        $h = $z | Where-Object { $_ -match '^HostUrl=' } | Select-Object -First 1
        $r = $z | Where-Object { $_ -match '^ReferrerUrl=' } | Select-Object -First 1
        $o = @()
        if ($h) { $o += ($h -replace '^HostUrl=', '') }
        if ($r) { $o += ('ref: ' + ($r -replace '^ReferrerUrl=', '')) }
        return ($o -join ' | ')
    } catch { return '' }
}
function Get-Magic([string]$p) {
    try {
        $fs = [IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
        $n = 0
        $buf = New-Object byte[] 4
        try { $n = $fs.Read($buf, 0, 4) } finally { $fs.Dispose() }
        if ($n -ge 2 -and $buf[0] -eq 0x4D -and $buf[1] -eq 0x5A) { return 'MZ' }
        if ($n -ge 4 -and $buf[0] -eq 0x50 -and $buf[1] -eq 0x4B -and $buf[2] -eq 3 -and $buf[3] -eq 4) { return 'PK' }
        if ($n -ge 2) { return 'OTHER' }
    } catch {}
    return ''
}
function Get-KeyTime($k) {
    if ($script:HkOk) { try { return (Ft ([HkNative]::KeyTime($k.Handle))) } catch {} }
    return $null
}
function Test-PathInfo([string]$p) {
    $r = @{ Exists = $false; Removed = $false }
    if ($p -match '^([A-Za-z]:)\\') {
        $dl = $Matches[1].ToUpper()
        if ($script:Drives -contains $dl) { $r.Exists = [bool](Test-Path -LiteralPath $p) } else { $r.Removed = $true }
    } elseif ($p -match '^\(') {
        $r.Removed = $true
    } else {
        $r.Exists = [bool](Test-Path -LiteralPath $p)
    }
    return $r
}
function Resolve-NtPath([string]$p) {
    $r = @{ Path = $p; Exists = $false; Removed = $false }
    if ($p -match '^(\\Device\\HarddiskVolume\d+)(\\.*)$') {
        $dev = $Matches[1]
        $rest = $Matches[2]
        if ($script:VolMap.ContainsKey($dev)) {
            $r.Path = $script:VolMap[$dev] + $rest
            $r.Exists = [bool](Test-Path -LiteralPath $r.Path)
        } else {
            $found = $false
            if (-not $script:HkOk) {
                foreach ($dl in $script:Drives) {
                    if (Test-Path -LiteralPath ($dl + $rest)) { $r.Path = $dl + $rest; $r.Exists = $true; $found = $true; break }
                }
            }
            if (-not $found -and -not $r.Exists) { $r.Path = '(cikarilmis/eski surucu)' + $rest; $r.Removed = $true }
        }
    } else {
        $pi = Test-PathInfo $p
        $r.Exists = $pi.Exists
        $r.Removed = $pi.Removed
    }
    return $r
}
function Resolve-PfPath([string]$p) {
    $r = @{ Path = $p; Exists = $false; Removed = $false }
    if ($p -match '^\\VOLUME\{[0-9a-fA-F]+-([0-9a-fA-F]{8})\}(\\.*)$') {
        $ser = $Matches[1].ToUpper()
        $rest = $Matches[2]
        if ($script:SerialMap.ContainsKey($ser)) {
            $r.Path = $script:SerialMap[$ser] + $rest
            $r.Exists = [bool](Test-Path -LiteralPath $r.Path)
        } else {
            $r.Path = '(cikarilmis/eski surucu)' + $rest
            $r.Removed = $true
        }
    }
    return $r
}
function Rot13([string]$s) {
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $s.ToCharArray()) {
        $c = [int]$ch
        if ($c -ge 65 -and $c -le 90) { $c = ((($c - 65 + 13) % 26) + 65) } elseif ($c -ge 97 -and $c -le 122) { $c = ((($c - 97 + 13) % 26) + 97) }
        [void]$sb.Append([char]$c)
    }
    return $sb.ToString()
}
function Get-DownloadsPath {
    try {
        $v = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -ErrorAction Stop).'{374DE290-123F-4565-9164-39C4925E467B}'
        if ($v) { return [Environment]::ExpandEnvironmentVariables($v) }
    } catch {}
    return (Join-Path $env:USERPROFILE 'Downloads')
}

function Add-Sys([string]$Baslik, [int]$Skor, [string]$Aciklama, $Zaman = $null, [string]$Durum = '', $Degisim = $null) {
    [void]$script:Sys.Add([pscustomobject]@{ Baslik = $Baslik; Skor = $Skor; Aciklama = $Aciklama; Zaman = $Zaman; Durum = $Durum; Degisim = $Degisim })
}
# Bir servisin durumunu (baslatma modu + calisip calismadigi) ve kayit defteri anahtarinin
# en son ne zaman elle degistirildigini (Degisim) birlikte raporlar.
function Check-Service([string]$sv, [string]$aciklama, [int]$devreDisiSkor = 40, [int]$durdurulmusSkor = 30) {
    $s = Get-CimInstance Win32_Service -Filter ("Name='" + $sv + "'")
    if (-not $s) { return }
    $kt = $null
    try {
        $k = (Get-Item -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $sv))
        $kt = Get-KeyTime $k
    } catch {}
    $durum = $sv + ': baslatma=' + $s.StartMode + ', durum=' + $s.State
    if ($s.StartMode -eq 'Disabled') {
        Add-Sys ('Servis DEVRE DISI: ' + $sv) $devreDisiSkor $aciklama $null $durum $kt
    } elseif ($s.State -ne 'Running' -and $s.StartMode -eq 'Auto') {
        Add-Sys ('Servis durdurulmus: ' + $sv) $durdurulmusSkor $aciklama $null $durum $kt
    } elseif ($kt -and $kt -gt (Get-Date).AddDays(-14)) {
        Add-Sys ('Servis ayari yakin zamanda degistirilmis: ' + $sv) 15 ($aciklama + ' (ayar 14 gun icinde degismis, normal olabilir)') $null $durum $kt
    }
}
# Bir kayit defteri DWORD degerini okur; beklenen (guvenli) degerden farkliysa uyari ekler,
# anahtarin en son ne zaman elle degistirildigini de raporlar.
function Check-RegFlag([string]$path, [string]$name, $beklenen, [string]$baslik, [string]$aciklama, [int]$skor) {
    try {
        $item = Get-Item -LiteralPath $path -ErrorAction Stop
        $val = $item.GetValue($name)
        $kt = Get-KeyTime $item
        if ($null -eq $val) { return }
        if ($val -ne $beklenen) {
            Add-Sys $baslik $skor $aciklama $null ($name + '=' + $val + ' (beklenen: ' + $beklenen + ')') $kt
        } elseif ($kt -and $kt -gt (Get-Date).AddDays(-14)) {
            Add-Sys ($baslik + ' - ayar yakin zamanda degistirilmis') 12 ($aciklama + ' (deger guvenli ama anahtar 14 gun icinde degismis)') $null ($name + '=' + $val) $kt
        }
    } catch {}
}
function Add-F {
    param([string]$Kaynak, [string]$Ad, [string]$Yol, [int]$Skor, $Son = $null, $Ilk = $null, [string]$Var = 'Bilinmiyor', $Silinme = $null, [string]$Not = '', [bool]$Benign = $false)
    [void]$script:F.Add([pscustomobject]@{ Kaynak = $Kaynak; Ad = $Ad; Yol = $Yol; Skor = $Skor; Son = $Son; Ilk = $Ilk; Var = $Var; Silinme = $Silinme; Not = $Not; Benign = $Benign })
}

# Calistirilmis bir program kaydini (Prefetch/BAM/UserAssist/Amcache/Shimcache/Recent) degerlendirir
$script:ExecExtSet = @('.exe','.dll','.scr','.com','.msi')
$script:CodeExtSet = @('.exe','.dll','.scr','.com','.msi','.jar','.bat','.cmd','.ps1','.vbs')
function Eval-Exec {
    param([string]$Kaynak, [string]$Path, [bool]$Exists = $false, [bool]$Removed = $false, $Last = $null, $First = $null, [string]$Note = '', [switch]$NoLoc)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    $leaf = $Path
    try { $leaf = Split-Path -Leaf $Path } catch {}
    if ([string]::IsNullOrWhiteSpace($leaf)) { return }
    $zone = 'other'
    if (-not $NoLoc) { $zone = Get-Zone $Path }
    $hit = Get-NameHit $leaf $true
    $extL = ''
    try { $extL = [IO.Path]::GetExtension($leaf).ToLower() } catch {}
    $isCode = ($script:CodeExtSet -contains $extL)
    $sc = 0
    $why = New-Object System.Collections.Generic.List[string]
    if ($hit) {
        $ns = Name-Score $hit $true
        if ($ns -gt 0) { $sc += $ns; [void]$why.Add('isim eslesmesi: ' + $hit.Name) }
    }
    # ONEMLI: isim eslesmesi YOKSA ve dosya calistirilabilir bir kod dosyasi (exe/dll/jar/bat/ps1 vs.) DEGILSE
    # (yani sadece bir arsiv/veri dosyasi ise: .zip/.rar/.7z/resource pack vb.) hicbir konum/imza puani verme.
    # Sirf "indirilenler klasorunde" veya "imzasiz" olmak (zip'lerin zaten imzasi olmaz) tek basina supheli degildir.
    if (-not $hit -and -not $isCode) { return }
    if (-not $NoLoc) {
        if ($zone -eq 'system' -and $sc -eq 0) { return }
        if ($Removed) {
            $sc += 30
            [void]$why.Add('cikarilmis/eski surucuden calistirilmis')
        } elseif ($zone -eq 'user' -or $zone -eq 'temp') {
            if (-not $Exists) {
                $sc += 30
                [void]$why.Add('kullanici/temp klasorunden calistirilmis, su an SILINMIS')
            } else {
                $sc += 12
                [void]$why.Add('kullanici/temp klasorunden calistirilmis')
                if (($script:ExecExtSet -contains $extL) -and -not (Test-Signed $Path)) { $sc += 20; [void]$why.Add('imzasiz calistirilabilir dosya') }
            }
        } elseif ($zone -eq 'shared') {
            if (-not $Exists) { $sc += 20; [void]$why.Add('ortak klasorden calistirilmis, SILINMIS') } elseif (($script:ExecExtSet -contains $extL) -and -not (Test-Signed $Path)) { $sc += 15; [void]$why.Add('ortak klasorde imzasiz program') }
        } elseif ($zone -eq 'appdata') {
            if (-not $Exists) { $sc += 12; [void]$why.Add('AppData programi, su an yok') }
        } elseif ($zone -eq 'other') {
            if (-not $Exists) { $sc += 12; [void]$why.Add('calistirilmis, su an bulunamiyor') }
        }
    }
    $benign = $false
    if (($leaf -match $script:BenignRx) -and $sc -lt 40) { $benign = $true; $sc -= 15 }
    if ($sc -lt 10) { return }
    $var = 'Bilinmiyor'
    if (-not $NoLoc) { if ($Exists) { $var = 'Evet' } else { $var = 'Hayir' } }
    $nt = ($why -join '; ')
    if ($Note) { $nt = $nt + ' | ' + $Note }
    if ($Exists -and $sc -ge 20) {
        $zi = Get-ZoneInfo $Path
        if ($zi) { $nt = $nt + ' | indirildigi adres: ' + $zi }
    }
    Add-F -Kaynak $Kaynak -Ad $leaf.ToLower() -Yol $Path -Skor ([Math]::Min(100, $sc)) -Son $Last -Ilk $First -Var $var -Not $nt -Benign $benign
}

function Inspect-Jar([string]$p) {
    $r = @{ Hit = $null; Agent = $false; AgentClass = '' }
    try {
        $zip = [IO.Compression.ZipFile]::OpenRead($p)
        try {
            foreach ($e in $zip.Entries) {
                $n = $e.FullName
                if (-not $r.Hit -and $n.EndsWith('.class')) {
                    $h = Get-NameHit $n $false
                    if ($h) { $r.Hit = $h.Name }
                }
                if ($n -eq 'META-INF/MANIFEST.MF') {
                    $sr = New-Object IO.StreamReader($e.Open())
                    $txt = $sr.ReadToEnd()
                    $sr.Dispose()
                    if ($txt -match '(?im)^(Premain-Class|Agent-Class|Launcher-Agent-Class):\s*(\S+)') { $r.Agent = $true; $r.AgentClass = $Matches[2] }
                }
            }
        } finally { $zip.Dispose() }
    } catch {}
    return $r
}

function Inspect-File($f) {
    $script:fileCount++
    if (($script:fileCount % 3000) -eq 0) { Write-Host -NoNewline '.' -ForegroundColor DarkGray }
    $name = $f.Name
    $ext = $f.Extension.ToLower()
    $path = $f.FullName
    $isInt = ($IntExt -contains $ext)
    $sc = 0
    $why = New-Object System.Collections.Generic.List[string]

    if (($ext -eq '.log' -or $ext -eq '.gz' -or $ext -eq '.txt') -and ($path -match '(?i)\\(logs|crash-reports)\\') -and ($path -match $script:LauncherRx)) {
        [void]$script:LogCand.Add($f)
    }
    if ($name -like 'launcher_profiles*.json') { [void]$script:ProfileJsonCand.Add($f) }
    if ($ext -eq '.json' -and $f.Length -lt 3145728 -and ($path -match '(?i)\\\.minecraft\\versions\\|feather')) { [void]$script:JsonCand2.Add($f) }
    if ($isInt -or $ext -eq '') {
        $hit = Get-NameHit $name $true
        if ($hit) {
            $ns = Name-Score $hit $true
            if ($ns -gt 0) { $sc += $ns; [void]$why.Add('dosya adi: ' + $hit.Name) }
        }
    }
    if ($name -match '(?i)\.(png|jpe?g|gif|txt|pdf|docx?|xlsx?|mp3|mp4|zip|rar|lnk)\.(exe|scr|bat|cmd|jar|com|vbs|ps1|dll)$') {
        $sc += 55; [void]$why.Add('cift uzanti (gizlenmis calistirilabilir dosya)')
    }
    if ($name.IndexOf([char]0x202E) -ge 0) { $sc += 60; [void]$why.Add('RTLO (ters yazdirma) uzanti hilesi') }

    $heavy = ($path -notmatch $HeavyRx)
    $magic = ''
    $disg = ($DisguiseExt -contains $ext)
    if ($f.Length -ge 4 -and $heavy) {
        if (($disg -and $f.Length -ge 20480) -or ($ext -eq '' -and $f.Length -ge 20480) -or $ext -eq '.jar' -or $ext -eq '.exe' -or $ext -eq '.dll') { $magic = Get-Magic $path }
    }
    if ($magic -eq 'MZ' -and ($disg -or $ext -eq '')) {
        $extTxt = $ext
        if (-not $extTxt) { $extTxt = '(uzantisiz)' }
        $sc += 60; [void]$why.Add('uzanti ' + $extTxt + ' ama icerik EXE/DLL (MZ) - uzanti degistirilmis/silinmis')
    } elseif ($magic -eq 'PK' -and $disg) {
        $sc += 45; [void]$why.Add('uzanti ' + $ext + ' ama icerik ZIP/JAR (PK) - uzanti degistirilmis')
    } elseif ($magic -eq 'OTHER' -and $ext -eq '.jar') {
        $sc += 35; [void]$why.Add('.jar uzantili ama gercek jar/zip degil (sifreli/bozuk olabilir)')
    } elseif ($magic -eq 'OTHER' -and ($ext -eq '.exe' -or $ext -eq '.dll')) {
        $sc += 40; [void]$why.Add($ext + ' uzantili ama gercek program degil')
    }
    if ($heavy -and ($ext -eq '.jar' -or ($magic -eq 'PK' -and $disg)) -and $f.Length -lt 157286400) {
        $jr = Inspect-Jar $path
        if ($jr.Hit) { $sc += 40; [void]$why.Add('jar ICINDE hile modulu/istemci ismi: ' + $jr.Hit) }
        if ($jr.Agent) { $sc += 30; [void]$why.Add('jar bir Java agent (' + $jr.AgentClass + ') - oyuna kod enjekte edebilir') }
    }
    if ($script:HkOk -and $heavy) {
        $adsList = $null
        try { $adsList = [HkNative]::Streams($path) } catch {}
        foreach ($stx in @($adsList)) {
            if (-not $stx) { continue }
            $sp = ([string]$stx).Split('|')
            $sn = $sp[0]
            if ($sn -eq '::$DATA') { continue }
            $nm = ($sn -replace '^:', '') -replace ':\$DATA$', ''
            if ($nm -match '^(Zone\.Identifier|Win32App_\d+|SmartScreen|encryptable|com\.dropbox\.attrs|com\.dropbox\.attributes|AFP_AfpInfo|OECustomProperty)$') { continue }
            $ssz = [long]0
            [void][long]::TryParse($sp[1], [ref]$ssz)
            $adsSc = 30
            $adsWhy = 'gizli veri akisi (ADS): ' + $nm + ' (' + $ssz + ' bayt)'
            if ($ssz -ge 1024) { $adsSc = 45 }
            if ($nm -match '(?i)\.(exe|dll|jar|bat|ps1|cmd|vbs)$') { $adsSc = [Math]::Max($adsSc, 60); $adsWhy += ' - kod uzantili' }
            if ($ssz -ge 2) {
                try {
                    $hb = @(Get-Content -LiteralPath $path -Stream $nm -Encoding Byte -TotalCount 2 -ErrorAction Stop)
                    if ($hb.Count -ge 2 -and $hb[0] -eq 0x4D -and $hb[1] -eq 0x5A) { $adsSc = 80; $adsWhy += ' - icerik EXE/DLL (MZ)' }
                } catch {}
            }
            Add-F -Kaynak 'ADS (gizli veri akisi)' -Ad ($name.ToLower() + ':' + $nm.ToLower()) -Yol ($path + ':' + $nm) -Skor $adsSc -Son $f.LastWriteTime -Ilk $f.CreationTime -Var 'Evet' -Not $adsWhy
        }
    }
    if ($ext -eq '.exe' -and ($path -match $SigRx)) {
        if (-not (Test-Signed $path)) { $sc += 20; [void]$why.Add('imzasiz exe') }
    }
    if ($sc -ge 10) {
        $nt = ($why -join '; ')
        if ($isInt) {
            $zi = Get-ZoneInfo $path
            if ($zi) { $nt = $nt + ' | indirildigi adres: ' + $zi }
        }
        Add-F -Kaynak 'Dosya taramasi' -Ad $name.ToLower() -Yol $path -Skor ([Math]::Min(100, $sc)) -Son $f.LastWriteTime -Ilk $f.CreationTime -Var 'Evet' -Not $nt
    }
}

function Read-Prefetch([string]$file) {
    $res = @{ Runs = @(); Paths = @(); Exe = '' }
    try {
        $raw = [IO.File]::ReadAllBytes($file)
        $data = $raw
        if ($raw.Length -gt 8 -and $raw[0] -eq 0x4D -and $raw[1] -eq 0x41 -and $raw[2] -eq 0x4D) {
            if (-not $script:HkOk) { return $res }
            $usize = [BitConverter]::ToUInt32($raw, 4)
            $comp = New-Object byte[] ($raw.Length - 8)
            [Array]::Copy($raw, 8, $comp, 0, $comp.Length)
            $data = [HkNative]::Xpress($comp, $usize)
        }
        if ($null -eq $data -or $data.Length -lt 200) { return $res }
        if ([Text.Encoding]::ASCII.GetString($data, 4, 4) -ne 'SCCA') { return $res }
        $ver = [BitConverter]::ToUInt32($data, 0)
        $res.Exe = [Text.Encoding]::Unicode.GetString($data, 16, 60).Split([char]0)[0]
        $runs = @()
        if ($ver -ge 26) {
            for ($i = 0; $i -lt 8; $i++) {
                $t = Ft ([BitConverter]::ToInt64($data, 128 + 8 * $i))
                if ($t) { $runs += $t }
            }
        } elseif ($ver -eq 23) {
            $t = Ft ([BitConverter]::ToInt64($data, 128))
            if ($t) { $runs += $t }
        } elseif ($ver -eq 17) {
            $t = Ft ([BitConverter]::ToInt64($data, 120))
            if ($t) { $runs += $t }
        }
        $res.Runs = $runs
        $so = [BitConverter]::ToUInt32($data, 100)
        $sl = [BitConverter]::ToUInt32($data, 104)
        if ($so -gt 0 -and $sl -gt 0 -and ($so + $sl) -le $data.Length) {
            $s = [Text.Encoding]::Unicode.GetString($data, $so, $sl)
            $res.Paths = @($s.Split([char]0) | Where-Object { $_ })
        }
    } catch {}
    return $res
}

function Read-LogText([string]$p) {
    try {
        if ($p -like '*.gz') {
            $fs = [IO.File]::OpenRead($p)
            $gz = New-Object IO.Compression.GZipStream($fs, [IO.Compression.CompressionMode]::Decompress)
            $sr = New-Object IO.StreamReader($gz)
            $t = $sr.ReadToEnd()
            $sr.Dispose(); $gz.Dispose(); $fs.Dispose()
            return $t
        }
        $fs2 = [IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
        $sr2 = New-Object IO.StreamReader($fs2)
        $t2 = $sr2.ReadToEnd()
        $sr2.Dispose(); $fs2.Dispose()
        return $t2
    } catch { return '' }
}

function Get-UsnTime([string]$ln) {
    $m = [regex]::Match($ln, '(\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4})[ T,]+(\d{1,2}:\d{2}:\d{2}(?:\s?[AaPp][Mm])?)')
    if (-not $m.Success) { return $null }
    $s = $m.Groups[1].Value + ' ' + $m.Groups[2].Value
    $d = [datetime]::MinValue
    if ([datetime]::TryParse($s, [Globalization.CultureInfo]::CurrentCulture, [Globalization.DateTimeStyles]::None, [ref]$d)) { return $d }
    if ([datetime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$d)) { return $d }
    return $null
}
function Get-UsnName([string]$ln) {
    foreach ($tok in $ln.Split(',')) {
        $t = $tok.Trim().Trim('"').Trim()
        if (-not $t) { continue }
        if ($t -match '^0x[0-9A-Fa-f]+$') { continue }
        if ($t -match '^\d+$') { continue }
        if ($t -match '[\\/:*?<>|]') { continue }
        if ($t -match '^\$I[A-Za-z0-9]{6}(\.|$)' -or $t -match '\.[A-Za-z0-9]{1,5}$') { return $t }
    }
    return $null
}
function Test-UsnDelete([string]$ln) {
    if ($ln -match '(?i)file delete') { return $true }
    foreach ($mm in [regex]::Matches($ln, '0x[0-9A-Fa-f]{8}(?![0-9A-Fa-f])')) {
        $val = [Convert]::ToUInt32($mm.Value.Substring(2), 16)
        if (($val -band 0x200) -ne 0) { return $true }
    }
    return $false
}
function Read-Usn([string]$dl) {
    $id = [guid]::NewGuid().ToString('N')
    $tmpCmd = Join-Path $env:TEMP ('hk_usn_' + $id + '.cmd')
    $tmpOut = Join-Path $env:TEMP ('hk_usn_' + $id + '.txt')
    $cmdText = "@echo off`r`nfsutil usn readjournal " + $dl + " csv | findstr /i /c:`".exe`" /c:`".jar`" /c:`".rar`" /c:`".zip`" /c:`".7z`" /c:`".dll`" /c:`".bat`" /c:`".ps1`" /c:`"`$I`" > `"" + $tmpOut + "`"`r`n"
    try {
        Set-Content -LiteralPath $tmpCmd -Value $cmdText -Encoding ASCII
        & $tmpCmd | Out-Null
    } catch {}
    $lines = @()
    if (Test-Path -LiteralPath $tmpOut) { $lines = @(Get-Content -LiteralPath $tmpOut -ErrorAction SilentlyContinue) }
    Remove-Item -LiteralPath $tmpCmd -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tmpOut -Force -ErrorAction SilentlyContinue
    $cnt = 0
    $cut = (Get-Date).AddDays(-30)
    foreach ($ln in $lines) {
        if (-not (Test-UsnDelete $ln)) { continue }
        $nm = Get-UsnName $ln
        if (-not $nm) { continue }
        $tm = Get-UsnTime $ln
        $key = $nm.ToLower()
        if ($nm -match '^\$I[A-Za-z0-9]{6}(\.|$)') {
            if ($tm) {
                if (-not $script:BinEmptied.ContainsKey($dl) -or $tm -gt $script:BinEmptied[$dl]) { $script:BinEmptied[$dl] = $tm }
            }
            continue
        }
        if ($nm -match '^\$R') { continue }
        $cnt++
        if ($tm) {
            if (-not $script:UsnDel.ContainsKey($key) -or $tm -gt $script:UsnDel[$key]) { $script:UsnDel[$key] = $tm }
        }
        $ext = ''
        try { $ext = [IO.Path]::GetExtension($nm).ToLower() } catch {}
        $hit = Get-NameHit $nm $true
        $ns = 0
        if ($hit) { $ns = Name-Score $hit $true }
        if ($ns -gt 0) {
            Add-F -Kaynak 'USN silinme kaydi' -Ad $key -Yol $nm -Skor ($ns + 5) -Var 'Hayir' -Silinme $tm -Not ('dosya silinmis (USN gunlugu): ' + $hit.Name)
        }
        if ($tm -and $tm -ge $cut -and @('.exe', '.jar', '.rar', '.zip', '.7z', '.bat', '.ps1') -contains $ext) {
            [void]$script:UsnRecent.Add([pscustomobject]@{ Ad = $nm; Zaman = $tm; Surucu = $dl })
        }
    }
    return $cnt
}

function Add-Root([string]$r) {
    if ([string]::IsNullOrWhiteSpace($r)) { return }
    if (-not (Test-Path -LiteralPath $r)) { return }
    $r = $r.TrimEnd('\')
    foreach ($e in $script:ScanRoots) {
        if ($r -ieq $e -or $r.StartsWith($e + '\', [StringComparison]::OrdinalIgnoreCase)) { return }
    }
    [void]$script:ScanRoots.Add($r)
}

$script:mF = 0
$script:mS = 0

function Find-Paths([string]$text, [string]$exts) {
    $res = New-Object System.Collections.Generic.List[string]
    $pat = '[A-Za-z]:\\[^\x00-\x1f"<>|*?:]{3,260}?\.(?:' + $exts + ')(?![A-Za-z0-9])'
    try {
        $rx = New-Object System.Text.RegularExpressions.Regex ($pat, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase, [TimeSpan]::FromSeconds(25))
        foreach ($m in $rx.Matches($text)) { [void]$res.Add($m.Value) }
    } catch {}
    return $res
}
# Fileless / script kalibi: Invoke-*, Reflection.Assembly, base64, gizli pencere vb. (tek basina BAN sebebi degil, supheli)
$script:FlRx2 = '(?i)Invoke-Expression|Invoke-RestMethod|Invoke-WebRequest|Invoke-Command|Invoke-Shellcode|\bIEX\b|System\.Reflection\.Assembly|\[Reflection\.Assembly\]|DownloadString|DownloadFile|FromBase64String|-enc(odedcommand)?\s|-w(indowstyle)?\s+hidden|-ExecutionPolicy\s+Bypass|\bmshta\b|certutil.*-urlcache|bitsadmin.*transfer|wmic\s+.*process\s+call\s+create'

# Byte dizisinden (registry binary / XML / PIDL) dosya yolu ve dosya adi cikarir (hem UTF-16 hem ASCII okunur)
function Get-PathsFromBytes([byte[]]$b, [bool]$namesToo = $false) {
    $res = New-Object System.Collections.Generic.List[string]
    if ($null -eq $b -or $b.Length -lt 8) { return $res }
    $seen = @{}
    $texts = New-Object System.Collections.Generic.List[string]
    foreach ($off in @(0, 1)) {
        $len = $b.Length - $off
        if ($len -lt 4) { continue }
        $sub = New-Object byte[] $len
        [Array]::Copy($b, $off, $sub, 0, $len)
        [void]$texts.Add([Text.Encoding]::Unicode.GetString($sub))
    }
    [void]$texts.Add([Text.Encoding]::GetEncoding(28591).GetString($b))
    foreach ($t in $texts) {
        foreach ($p in (Find-Paths $t 'exe|dll|jar|bat|ps1|scr|cmd|vbs|com')) {
            $k = $p.ToLower()
            if (-not $seen.ContainsKey($k)) { $seen[$k] = 1; [void]$res.Add($p) }
        }
        if ($namesToo) {
            foreach ($m in [regex]::Matches($t, '(?i)(?<![\w.\-\\/])[\w\-.]{2,80}\.(?:exe|dll|jar|bat|ps1|scr|cmd|vbs)(?![\w])')) {
                $k = $m.Value.ToLower()
                if (-not $seen.ContainsKey($k)) { $seen[$k] = 1; [void]$res.Add($m.Value) }
            }
        }
    }
    return $res
}

$script:PiCache = @{}
function Get-PiCached([string]$p) {
    $k = $p.ToLower()
    if (-not $script:PiCache.ContainsKey($k)) { $script:PiCache[$k] = Test-PathInfo $p }
    return $script:PiCache[$k]
}

# ---------------- process bellegi (RAM) string analizi ----------------
# .exe/.dll/.jar... yolu ve dosya adi iceren stringler: bilinen hile isimleri, silinmis/olagan disi yerden calisanlar
function Analyze-MemExe([string]$label, $strings, [int]$procId) {
    if ($null -eq $strings -or $strings.Count -eq 0) { return }
    $text = [string]::Join("`n", $strings)
    $seenP = @{}
    $cnt = 0
    foreach ($pm in (Find-Paths $text 'exe|dll|jar|bat|ps1|scr|cmd|vbs|com')) {
        $lk = $pm.ToLower()
        if ($seenP.ContainsKey($lk)) { continue }
        $seenP[$lk] = 1
        $leaf = ''
        try { $leaf = Split-Path -Leaf $pm } catch {}
        if (-not $leaf) { continue }
        $zone = Get-Zone $pm
        $hit = Get-NameHit $leaf $false
        if ($zone -eq 'system' -and -not $hit) { continue }
        $cnt++
        if ($cnt -gt 3000) { break }
        $pi = Get-PiCached $pm
        Eval-Exec -Kaynak ('Bellek stringi: ' + $label) -Path $pm -Exists $pi.Exists -Removed $pi.Removed -Note ('process bellegindeki yol (PID ' + $procId + ')')
    }
    $seenN = @{}
    foreach ($m in [regex]::Matches($text, '(?i)(?<![\w.\-\\/])([\w\-]{2,60})\.(?:exe|dll|jar)(?![\w])')) {
        $leaf = $m.Value
        $lk = $leaf.ToLower()
        if ($seenN.ContainsKey($lk)) { continue }
        $seenN[$lk] = 1
        $hit = Get-NameHit $leaf $false
        if (-not $hit) { continue }
        Add-F -Kaynak ('Bellek stringi: ' + $label) -Ad $lk -Yol $leaf -Skor 45 -Var 'Bilinmiyor' -Not ('process bellegindeki dosya adi, hile ismi: ' + $hit.Name + ' (PID ' + $procId + ')')
    }
}
# DPS servisinin bellegindeki !!program.exe!yyyy/MM/dd:HH:mm:ss! kayitlari (calistirma zamani)
function Analyze-MemDps([string]$label, $strings, [int]$procId) {
    if ($null -eq $strings -or $strings.Count -eq 0) { return }
    $text = [string]::Join("`n", $strings)
    $seen = @{}
    foreach ($m in [regex]::Matches($text, '!!([^!\\/\r\n]{2,80}\.(?:exe|dll))!(\d{4}/\d{2}/\d{2}:\d{2}:\d{2}:\d{2})!')) {
        $n = $m.Groups[1].Value
        $hit = Get-NameHit $n $false
        if (-not $hit) { continue }
        $key = $n.ToLower() + '|' + $m.Groups[2].Value
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = 1
        $tm = $null
        try { $tm = [datetime]::ParseExact($m.Groups[2].Value, 'yyyy/MM/dd:HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) } catch {}
        Add-F -Kaynak ('Bellek stringi: ' + $label + ' (DPS kaydi)') -Ad $n.ToLower() -Yol $n -Skor 50 -Son $tm -Var 'Bilinmiyor' -Not ('DPS bellek kaydi: calistirilmis program, hile ismi: ' + $hit.Name)
    }
}
# Dnscache bellegindeki alan adlari: hile site/istemci isimleri
function Analyze-MemDns([string]$label, $strings, [int]$procId) {
    if ($null -eq $strings -or $strings.Count -eq 0) { return }
    $text = [string]::Join("`n", $strings)
    $seen = @{}
    foreach ($m in [regex]::Matches($text, '(?i)(?<![a-z0-9\-])[a-z0-9][a-z0-9\-]{1,40}(?:\.[a-z0-9\-]{1,30})*\.(?:com|net|org|gg|io|xyz|ru|to|cc|club|pw|dev|me|app|su|cloud|shop|store|lol|fun|top|info|site|online|space|tech|cx|ws)(?![a-z0-9])')) {
        $d = $m.Value.ToLower()
        if ($seen.ContainsKey($d)) { continue }
        $seen[$d] = 1
        if ($seen.Count -gt 20000) { break }
        $hit = Get-NameHit $d $false
        if (-not $hit) { continue }
        Add-F -Kaynak ('Bellek stringi: ' + $label + ' (DNS)') -Ad ('alan adi: ' + $d) -Yol $d -Skor 45 -Var 'Bilinmiyor' -Not ('DNS onbellegi/bellek: bu alan adina baglanilmis olabilir, hile ismi: ' + $hit.Name)
    }
}
# wmic ile program baslatma komutlari (wmic ... process call create)
function Analyze-MemWmic([string]$label, $strings, [int]$procId) {
    if ($null -eq $strings -or $strings.Count -eq 0) { return }
    $seen = @{}
    foreach ($s in $strings) {
        if ($s.IndexOf('wmic', [StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        $sc = 0
        if ($s -match '(?i)wmic(\.exe)?\s+.*process\s+call\s+create') { $sc = 60 }
        elseif ($s -match '(?i)wmic(\.exe)?\s+\S.*\.(exe|dll|bat|ps1|jar)') { $sc = 40 }
        if ($sc -eq 0) { continue }
        $k = $s.ToLower()
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = 1
        if ($seen.Count -gt 10) { break }
        $snip = $s
        if ($snip.Length -gt 220) { $snip = $snip.Substring(0, 220) + '...' }
        Add-F -Kaynak ('Bellek stringi: ' + $label + ' (wmic)') -Ad 'wmic ile program baslatma' -Yol $snip -Skor $sc -Var 'Bilinmiyor' -Not ('komut: ' + $snip + ' (PID ' + $procId + ') - exe/uzantisiz dosya/ADS baslatmak icin kullanilir')
    }
}
function Scan-MemProcess([string]$label, [int]$procId, [string]$rx, [string]$mode) {
    Log ('   bellek taraniyor: ' + $label + ' (PID ' + $procId + ')') 'DarkGray'
    $list = $null
    try { $list = [HkNative]::MemStrings($procId, $rx, 5, $true, $true, $false, [long]734003200) } catch { $list = $null }
    if ($null -eq $list) { $script:MemFail++; [void]$script:MemFailNames.Add($label); return }
    $script:MemOk++
    if ($mode -eq 'dns') { Analyze-MemDns $label $list $procId; return }
    Analyze-MemExe $label $list $procId
    if ($mode -eq 'dps') { Analyze-MemDps $label $list $procId }
    if ($mode -eq 'wmic') { Analyze-MemWmic $label $list $procId }
}

function Get-DelTime($x) {
    if ($x.Silinme) { return $x.Silinme }
    if ($x.Var -eq 'Hayir') {
        $k = ([string]$x.Ad).ToLower()
        if ($script:UsnDel.ContainsKey($k)) { return $script:UsnDel[$k] }
        foreach ($b in $script:BinItems) { if ($b.Orijinal -ieq $x.Yol) { return $b.Silinme } }
    }
    return $null
}
function Show-Finding($x) {
    $col = 'Yellow'
    if ($x.Skor -ge 60) { $col = 'Red' }
    Log '' 'Gray'
    Log ('   [%' + $x.Skor + ' hile ihtimali] ' + $x.Ad) $col
    Log ('      Konum            : ' + $x.Yol) 'Gray'
    $durum = 'DURUYOR'
    if ($x.Var -eq 'Hayir') {
        $dt = Get-DelTime $x
        if ($dt) { $durum = 'SILINMIS - silinme zamani: ' + (Fmt $dt) } else { $durum = 'SILINMIS - silinme zamani kayitlarda bulunamadi' }
    } elseif ($x.Var -eq 'Bilinmiyor') {
        $durum = 'bilinmiyor (yol kaydi yok)'
    }
    Log ('      Durum            : ' + $durum) 'Gray'
    Log ('      En son calistirma: ' + (Fmt $x.Son)) 'Gray'
    Log ('      Ilk gorulme/indirme: ' + (Fmt $x.Ilk)) 'Gray'
    Log ('      Bulundugu yer    : ' + $x.Kaynak) 'DarkGray'
    if ($x.Not) { Log ('      Detay            : ' + $x.Not) 'DarkGray' }
}
function Start-Sec {
    $script:mF = $script:F.Count
    $script:mS = $script:Sys.Count
}
function Show-Section {
    for ($i = $script:mS; $i -lt $script:Sys.Count; $i++) {
        $s = $script:Sys[$i]
        $zt = ''
        if ($s.Zaman) { $zt = ' [' + (Fmt $s.Zaman) + ']' }
        Log ('   ! [%' + $s.Skor + '] ' + $s.Baslik + $zt) 'Yellow'
        Log ('        ' + $s.Aciklama) 'DarkGray'
    }
    $items = @()
    for ($i = $script:mF; $i -lt $script:F.Count; $i++) { $items += $script:F[$i] }
    $sel = @($items | Where-Object { $_.Skor -ge 30 -and -not $_.Benign } | Sort-Object -Property @{ Expression = 'Skor'; Descending = $true }, @{ Expression = 'Son'; Descending = $true })
    $rest = $items.Count - $sel.Count
    if ($sel.Count -eq 0) { Log '   -> supheli bulgu yok' 'Green' }
    foreach ($x in ($sel | Select-Object -First 15)) { Show-Finding $x }
    if ($sel.Count -gt 15) { Log ('   ... +' + ($sel.Count - 15) + ' bulgu daha (rapor dosyasinda)') 'DarkGray' }
    if ($rest -gt 0) { Log ('   (' + $rest + ' dusuk guvenli kayit daha - sadece rapor dosyasinda)') 'DarkGray' }
}

function Show-Item($m, [string]$color, [bool]$fileOnly = $false) {
    Log '' 'Gray' $fileOnly
    Log ('[%' + $m.Skor + '] ' + $m.Ad) $color $fileOnly
    Log ('   Yer            : ' + $m.Yol) 'Gray' $fileOnly
    $durum = 'DURUYOR'
    if ($m.Var -eq 'Hayir') {
        if ($m.Silinme) { $durum = 'SILINMIS - silinme zamani: ' + (Fmt $m.Silinme) } else { $durum = 'SILINMIS (silinme zamani kayitlarda bulunamadi)' }
    } elseif ($m.Var -eq 'Bilinmiyor') {
        $durum = 'bilinmiyor (yol kaydi yok)'
    }
    Log ('   Durum          : ' + $durum) 'Gray' $fileOnly
    Log ('   Son kullanim   : ' + (Fmt $m.Son) + '     Ilk gorulme/indirme: ' + (Fmt $m.Ilk)) 'Gray' $fileOnly
    Log ('   Kaynaklar      : ' + $m.Kaynaklar) 'Gray' $fileOnly
    if ($m.Not) { Log ('   Detay          : ' + $m.Not) 'DarkGray' $fileOnly }
}

# =====================================================================
Log '===================================================================' 'Green'
Log '  HileKiran - Minecraft hile / iz analizi' 'Green'
Log ('  Baslangic: ' + (Get-Date)) 'Green'
Log '  Not: Sadece bu bilgisayarda calisir, veri gondermez, hicbir seyi silmez.' 'DarkGray'
Log '===================================================================' 'Green'
if ($PSVersionTable.PSVersion.Major -lt 5) { Log 'UYARI: PowerShell 5+ gerekli, bazi kontroller calismayabilir.' 'Yellow' }
if (-not $script:HkOk) { Log 'UYARI: yardimci modul derlenemedi; Prefetch saatleri/USB/BAM yol cozumu kisitli olabilir.' 'Yellow' }

# ---------------------------------------------------------------------
Step '[1/16] BYPASS TESPITI - iz saklama/temizleme, servis ve ayar durumlari...'
Start-Sec
$pfDir = $env:WINDIR + '\Prefetch'
$pfFiles = @()
try { $pfFiles = @(Get-ChildItem -LiteralPath $pfDir -Filter '*.pf' -Force -ErrorAction Stop) } catch {}
$pfReg = $null
try { $pfReg = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -ErrorAction Stop).EnablePrefetcher } catch {}
if ($pfReg -eq 0) { Add-Sys 'Prefetch KAPATILMIS' 45 'EnablePrefetcher=0: Windows program calistirma kaydi tutmuyor (iz saklama girisimi olabilir).' }
if ($pfFiles.Count -eq 0) {
    Add-Sys 'Prefetch klasoru bos veya okunamadi' 40 'Normalde yuzlerce .pf dosyasi olur. Bos ise temizlenmis olabilir.'
} elseif ($pfFiles.Count -lt 20) {
    Add-Sys ('Prefetch klasorunde sadece ' + $pfFiles.Count + ' kayit var') 35 'Normalde cok daha fazla olur; yakin zamanda temizlenmis olabilir.'
} else {
    $oldest = ($pfFiles | Sort-Object CreationTime | Select-Object -First 1).CreationTime
    Log ('   Prefetch: ' + $pfFiles.Count + ' kayit, en eskisi: ' + (Fmt $oldest)) 'DarkGray'
}
Check-Service 'SysMain' 'Bu servis (eski adiyla Superfetch) Prefetch verisiyle iliskilidir; kapatilmasi iz saklama girisimi olabilir.' 40 30
Check-Service 'PcaSvc' 'Program Compatibility Assistant, calistirilan programlarla ilgili ek kayit tutar.' 35 15
Check-Service 'DPS' 'Diagnostic Policy Service - tanilama ve bazi kayit mekanizmalari buna baglidir.' 35 20
Check-Service 'EventLog' 'Windows Olay Gunlugu servisinin kendisi; kapaliysa hicbir olay kaydedilmez.' 60 50
Check-Service 'bam' 'BAM (Background Activity Moderator) - programlarin son calistirma zamanini tutar.' 45 30
Check-Service 'WinDefend' 'Windows Defender antivirus motoru.' 45 35
Check-Service 'WdNisSvc' 'Windows Defender ag denetimi.' 25 15
Check-Service 'Sense' 'Windows Defender gelismis tehdit koruma servisi.' 20 10
Check-Service 'wscsvc' 'Windows Guvenlik Merkezi servisi; antivirus/guvenlik duvarinin durumunu bildirir.' 30 20
Check-Service 'Appinfo' 'Uygulama Bilgisi servisi; yonetici izni isteyen programlarla ilgili kayit tutar.' 25 15
Check-Service 'mpssvc' 'Windows Guvenlik Duvari servisi.' 35 25
Check-Service 'Dnscache' 'DNS Istemci (Dnscache) servisi; hangi sitelere baglanildigina dair DNS onbellegini tutar.' 25 15
Check-Service 'BFE' 'Taban Filtre Motoru (BFE); guvenlik duvari kurallarini uygular, kapatilmasi tehlikeli.' 40 30
Check-Service 'DiagTrack' 'Baglanti Kullanici Deneyimleri ve Telemetri servisi.' 15 10
Check-Service 'WSearch' 'Windows Arama (SearchIndexer) servisi; dosya indeksleme ve arama gecmisini tutar.' 20 12

# --- Prefetch/Superfetch parametreleri (acik/kapali + en son elle degistirilme zamani) ---
Check-RegFlag 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' 'EnablePrefetcher' 3 'Prefetch (EnablePrefetcher) beklenenden farkli' 'Program calistirma onbellegi ayari degistirilmis (normal: 2 veya 3).' 40
Check-RegFlag 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' 'EnableSuperfetch' 3 'Superfetch ayari beklenenden farkli' 'Superfetch/SysMain onbellek ayari degistirilmis.' 25

# --- USN gunlugu / degisiklik gunlugu izleme ayari ---
Check-RegFlag 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' 'NtfsDisableLastAccessUpdate' 0 'Dosya erisim zamani guncellemesi KAPALI' 'Windows dosyalara en son erisim zamanini kaydetmiyor; adli analiz izlerini zayiflatir.' 30

# --- PowerShell komut/script kaydi (loglama) ---
Check-RegFlag 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1 'PowerShell ScriptBlock loglama KAPALI' 'PowerShell komutlarinin kaydi tutulmuyor; script tabanli islemler iz birakmaz.' 20

# --- Windows Defender kapatma bayraklari (grup ilkesi seviyesinde) ---
Check-RegFlag 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware' 0 'Windows Defender grup ilkesiyle KAPATILMIS' 'Antivirus grup ilkesi (registry) uzerinden devre disi birakilmis.' 55
Check-RegFlag 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection' 'DisableRealtimeMonitoring' 0 'Windows Defender aninda koruma KAPALI (registry)' 'Gercek zamanli tarama registry uzerinden kapatilmis.' 45

# --- Denetim (audit) ilkesi: nesne erisimi/sistem olaylari izleniyor mu ---
try {
    $apOut = & auditpol.exe /get /subcategory:"File System" 2>&1 | Out-String
    if ($apOut -match '(?i)No Auditing') { Add-Sys 'Dosya sistemi denetimi (audit) KAPALI' 15 'Dosya erisim/degisiklik olaylari Olay Gunlugune yazilmiyor (varsayilan zaten kapali olabilir).' }
} catch {}

# --- Zamanlanmis gorevler: log/prefetch/iz temizleyen komutlar iceren gorev var mi ---
$taskRoot = $env:WINDIR + '\System32\Tasks'
$cleanRx = '(?i)wevtutil\s+(cl|clear-log)|fsutil\s+usn\s+deletejournal|cipher\s*/w|del\s+/f.*prefetch|Clear-EventLog|Remove-Item.*Prefetch'
if (Test-Path -LiteralPath $taskRoot) {
    foreach ($tf in @(Get-ChildItem -LiteralPath $taskRoot -Recurse -File -Force -ErrorAction SilentlyContinue)) {
        $ttxt = ''
        try { $ttxt = Get-Content -LiteralPath $tf.FullName -Raw -ErrorAction Stop } catch {}
        if ($ttxt -and ($ttxt -match $cleanRx)) {
            Add-Sys ('Zamanlanmis gorev iz temizliyor: ' + $tf.Name) 45 'Bu gorev calistiginda log/prefetch/USN temizleme komutu iceriyor.' $tf.LastWriteTime ('gorev dosyasi: ' + $tf.FullName) $tf.LastWriteTime
        }
    }
}

# --- hosts dosyasi: yakin zamanda elle degistirilmis mi (anticheat/telemetri engelleme icin kullanilabilir) ---
$hostsPath = $env:WINDIR + '\System32\drivers\etc\hosts'
if (Test-Path -LiteralPath $hostsPath) {
    $hf = Get-Item -LiteralPath $hostsPath
    $hlines = @(Get-Content -LiteralPath $hostsPath -ErrorAction SilentlyContinue | Where-Object { $_ -and ($_.TrimStart() -notmatch '^#') })
    if ($hlines.Count -gt 5 -or ($hf.LastWriteTime -gt (Get-Date).AddDays(-30) -and $hlines.Count -gt 0)) {
        Add-Sys 'hosts dosyasi degistirilmis' 20 'Sistemin hosts dosyasinda ozel yonlendirme/engelleme kayitlari var (bazi hileler/anticheat atlatma araclari bunu kullanir).' $null ($hlines.Count.ToString() + ' ozel satir') $hf.LastWriteTime
    }
}
foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 1102 } -MaxEvents 5 -ErrorAction SilentlyContinue)) {
    Add-Sys 'Guvenlik olay gunlugu TEMIZLENMIS' 50 'Windows olay kaydi (Event 1102) silinmis.' $e.TimeCreated 'temizlenme zamani asagida' $e.TimeCreated
}
foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 104 } -MaxEvents 5 -ErrorAction SilentlyContinue)) {
    Add-Sys 'Sistem olay gunlugu TEMIZLENMIS' 50 'Windows olay kaydi (Event 104) silinmis.' $e.TimeCreated 'temizlenme zamani asagida' $e.TimeCreated
}
foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 1102 } -MaxEvents 5 -ErrorAction SilentlyContinue)) {
    Add-Sys 'Uygulama olay gunlugu TEMIZLENMIS' 45 'Windows olay kaydi (Event 1102) Uygulama gunlugunde silinmis.' $e.TimeCreated 'temizlenme zamani asagida' $e.TimeCreated
}
foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 3079 } -MaxEvents 5 -ErrorAction SilentlyContinue)) {
    Add-Sys 'Olay Gunlugu TEMIZLENMIS (3079)' 40 'Olay Goruntuleyicisi uzerinden bir log elle temizlenmis (Event 3079).' $e.TimeCreated 'temizlenme zamani asagida' $e.TimeCreated
}
# --- NTFS Operational log: USN Journal silinip yeniden olusturulmus mu (Event 501 tekrarlari = journal bypass) ---
try {
    $ntfsOp = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Ntfs/Operational'; Id = 501 } -MaxEvents 20 -ErrorAction Stop)
    if ($ntfsOp.Count -ge 2) {
        Add-Sys ('USN Journal birden fazla kez olusturulmus (' + $ntfsOp.Count + ' kayit)') 40 'Journal silinip yeniden olusturulmus olabilir (Event 501 NTFS Operational log, normalde nadir gorulur).' $ntfsOp[0].TimeCreated ('en son: ' + (Fmt $ntfsOp[0].TimeCreated)) $ntfsOp[0].TimeCreated
    }
} catch {}

# --- Prefetch dosya nitelikleri: Salt Okunur/Gizli yapilmis mi (Prefetch'in kaydetmesini engelleme yontemi) ---
$pfAttrBad = 0
$pfAttrExample = ''
foreach ($pf in $pfFiles) {
    if (($pf.Attributes -band [IO.FileAttributes]::ReadOnly) -or ($pf.Attributes -band [IO.FileAttributes]::Hidden)) {
        $pfAttrBad++
        if (-not $pfAttrExample) { $pfAttrExample = $pf.Name + ' (' + $pf.Attributes + ')' }
    }
}
if ($pfAttrBad -gt 0) {
    Add-Sys ('Prefetch dosyalarinda Salt Okunur/Gizli nitelik bulundu (' + $pfAttrBad + ' dosya)') 45 'Prefetch dosyasi Salt Okunur/Gizli yapilarak Windows''in yeni kayit yazmasi engellenebilir.' $null $pfAttrExample
}

# --- CMD AutoRun: her CMD acilista otomatik calisan komut (ozellikle kendini kapatan) ---
foreach ($arPath in @('HKLM:\SOFTWARE\Microsoft\Command Processor', 'HKCU:\SOFTWARE\Microsoft\Command Processor')) {
    try {
        $ar = (Get-ItemProperty -LiteralPath $arPath -Name AutoRun -ErrorAction Stop).AutoRun
        if ($ar) {
            $sc2 = 25
            if ($ar -match '(?i)taskkill|cmd\.exe.*\/f|cmd\.exe.*kill') { $sc2 = 50 }
            Add-Sys ('CMD AutoRun tanimli (' + $arPath + ')') $sc2 'CMD her acildiginda otomatik calisan bir komut var; CMD''yi kapatmak icin kullanilmis olabilir.' $null $ar
        }
    } catch {}
}

# --- CMD renk gizleme: yazi rengi = arka plan rengi (yazilanlari gizleme yontemi) ---
try {
    $cons = Get-ItemProperty -LiteralPath 'HKCU:\Console' -ErrorAction Stop
    if ($null -ne $cons.ScreenColors -and $null -ne $cons.PopupColors) {
        $fg = $cons.ScreenColors -band 0x0F
        $bg = ($cons.ScreenColors -band 0xF0) -shr 4
        if ($fg -eq $bg) {
            Add-Sys 'CMD yazi rengi arka plan rengiyle AYNI' 40 'Komut isterinde yazilanlar gorunmuyor olabilir (renk gizleme yontemi).' $null ('ScreenColors=0x' + [Convert]::ToString($cons.ScreenColors, 16))
        }
    }
    if ($null -ne $cons.ForceV2 -and $cons.ForceV2 -eq 0) {
        Add-Sys 'CMD eski konsol modunda (Legacy Console)' 20 'Kopyala/yapistir ve bazi ozellikler kapatilmis olabilir (eski konsol moduna alinarak).' $null 'ForceV2=0'
    }
} catch {}

# --- Internet Secenekleri Yasakli Siteler: anticheat/ss-tool sitelerini engelleme (indirme bypass) ---
try {
    $zoneRoot = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains'
    if (Test-Path -LiteralPath $zoneRoot) {
        $domains = New-Object System.Collections.Generic.List[string]
        foreach ($d in @(Get-ChildItem -LiteralPath $zoneRoot -ErrorAction SilentlyContinue)) {
            $sub = Get-ItemProperty -LiteralPath $d.PSPath -ErrorAction SilentlyContinue
            $hasRestricted = $false
            foreach ($p in $sub.PSObject.Properties) { if ($p.Name -notmatch '^PS' -and $p.Value -eq 4) { $hasRestricted = $true } }
            if ($hasRestricted) { [void]$domains.Add($d.PSChildName) }
            foreach ($d2 in @(Get-ChildItem -LiteralPath $d.PSPath -ErrorAction SilentlyContinue)) {
                $sub2 = Get-ItemProperty -LiteralPath $d2.PSPath -ErrorAction SilentlyContinue
                foreach ($p in $sub2.PSObject.Properties) { if ($p.Name -notmatch '^PS' -and $p.Value -eq 4) { [void]$domains.Add($d2.PSChildName + '.' + $d.PSChildName) } }
            }
        }
        if ($domains.Count -gt 0) {
            Add-Sys ('Internet Secenekleri Yasakli Siteler listesinde ' + $domains.Count + ' adres var') 25 'Bazi web siteleri "Yasakli Siteler" bolgesine eklenerek erisimi/indirmeyi engellemek icin kullanilabilir (anticheat/takip sitelerini engellemek gibi); listeyi elle kontrol et.' $null (($domains | Select-Object -First 5) -join ', ')
        }
    }
} catch {}
try {
    $mp = Get-MpPreference -ErrorAction Stop
    foreach ($x in @($mp.ExclusionPath)) {
        if ($x) {
            $z = Get-Zone $x
            if ($z -eq 'user' -or $z -eq 'temp' -or $x -match $script:LauncherRx -or $x -match '(?i)mods') { Add-Sys ('Defender dislama (klasor): ' + $x) 45 'Antivirus bu klasoru taramiyor; hile dosyalarini saklamak icin kullanilabilir.' } else { Add-Sys ('Defender dislama (klasor): ' + $x) 20 'Antivirus bu klasoru taramiyor.' }
        }
    }
    foreach ($x in @($mp.ExclusionProcess)) { if ($x) { Add-Sys ('Defender dislama (process): ' + $x) 35 'Antivirus bu programi taramiyor.' } }
    foreach ($x in @($mp.ExclusionExtension)) { if ($x) { Add-Sys ('Defender dislama (uzanti): ' + $x) 40 'Bu uzantili dosyalar taranmiyor.' } }
} catch {}
foreach ($pair in @(@('LGHUB', ($env:LOCALAPPDATA + '\LGHUB')), @('Razer Synapse', ($env:LOCALAPPDATA + '\Razer')), @('Bloody7', ($env:APPDATA + '\Bloody7')), @('SteelSeries', ($env:PROGRAMDATA + '\SteelSeries')))) {
    if (Test-Path -LiteralPath $pair[1]) { Add-Sys ('Fare/klavye yazilimi var: ' + $pair[0]) 15 'Makro/autoclick profili tanimlanmis olabilir (bu script profil icerigini okuyamaz).' (Get-Item -LiteralPath $pair[1]).LastWriteTime }
}
Show-Section

# ---------------------------------------------------------------------
Step '[2/16] Geri donusum kutusu ve USN gunlugu (silinen dosyalar, silinme zamanlari)...'
Start-Sec
foreach ($dl in $script:Drives) {
    $bin = $dl + '\$Recycle.Bin'
    if (-not (Test-Path -LiteralPath $bin)) { continue }
    $total = 0
    $latestDirChange = $null
    foreach ($sd in @(Get-ChildItem -LiteralPath $bin -Force -Directory -ErrorAction SilentlyContinue)) {
        if (-not $latestDirChange -or $sd.LastWriteTime -gt $latestDirChange) { $latestDirChange = $sd.LastWriteTime }
        foreach ($fi in @(Get-ChildItem -LiteralPath $sd.FullName -Force -Filter '$I*' -File -ErrorAction SilentlyContinue)) {
            try {
                $b = [IO.File]::ReadAllBytes($fi.FullName)
                if ($b.Length -lt 28) { continue }
                $ver = [BitConverter]::ToInt64($b, 0)
                $del = Ft ([BitConverter]::ToInt64($b, 16))
                $orig = ''
                if ($ver -eq 2) {
                    $plen = [BitConverter]::ToInt32($b, 24)
                    $take = [Math]::Min($plen * 2, $b.Length - 28)
                    $orig = [Text.Encoding]::Unicode.GetString($b, 28, $take).TrimEnd([char]0)
                } else {
                    $orig = [Text.Encoding]::Unicode.GetString($b, 24, $b.Length - 24).TrimEnd([char]0)
                }
                $rname = '$R' + $fi.Name.Substring(2)
                $still = Test-Path -LiteralPath (Join-Path $sd.FullName $rname)
                $total++
                [void]$script:BinItems.Add([pscustomobject]@{ Surucu = $dl; Orijinal = $orig; Silinme = $del; Kutuda = $still })
                $leaf = ''
                try { $leaf = Split-Path -Leaf $orig } catch {}
                if ($leaf) {
                    $bext = ''
                    try { $bext = [IO.Path]::GetExtension($leaf).ToLower() } catch {}
                    $bh = Get-NameHit $leaf $true
                    $bsc = 0
                    if ($bh) { $bsc += (Name-Score $bh $true) }
                    if (@('.exe', '.jar', '.rar', '.zip', '.7z', '.bat', '.ps1', '.scr') -contains $bext) { $bsc += 30 }
                    if ($bsc -ge 20) {
                        $bpi = Test-PathInfo $orig
                        $bvar = 'Hayir'
                        if ($bpi.Exists) { $bvar = 'Evet' }
                        $bnote = 'geri donusum kutusunda'
                        if (-not $still) { $bnote = 'geri donusum kutusu kaydi var ama dosya artik yok (kutu bosaltilmis)' }
                        Add-F -Kaynak 'Geri donusum kutusu' -Ad $leaf.ToLower() -Yol $orig -Skor ([Math]::Min(100, $bsc)) -Var $bvar -Silinme $del -Not $bnote -Benign ($bh -eq $null -and $leaf -match $script:BenignRx)
                    }
                }
            } catch {}
        }
    }
    if ($total -gt 0) { [void]$script:BinState.Add($dl + ' geri donusum kutusunda su an ' + $total + ' kayit var.') } else { [void]$script:BinState.Add($dl + ' geri donusum kutusu su an BOS.') }
    if ($latestDirChange) { [void]$script:BinState.Add('   ' + $dl + ' kutu klasoru son degisiklik: ' + (Fmt $latestDirChange) + ' (kutu bossa: yaklasik en son bosaltma/silme zamani)') }
}
foreach ($dl in $script:FixedNtfs) {
    & fsutil usn queryjournal $dl 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Add-Sys ('USN gunlugu YOK/silinmis: ' + $dl) 45 'USN gunlugu dosya silme/degistirme kayitlarini tutar; silinmis olmasi iz temizleme girisimi olabilir (fsutil usn deletejournal).'
        continue
    }
    Log ('   USN gunlugu okunuyor: ' + $dl + ' (biraz surebilir)...') 'DarkGray'
    $n = Read-Usn $dl
    Log ('   ' + $dl + ' : ' + $n + ' ilgili silme kaydi bulundu.') 'DarkGray'
}
Show-Section

# ---------------------------------------------------------------------
Step '[3/16] Calisan process, Java komut satiri, overlay pencereleri...'
Start-Sec
$procs = @(Get-CimInstance Win32_Process)
$SysNames = @('svchost', 'csrss', 'lsass', 'winlogon', 'services', 'smss', 'wininit', 'explorer', 'dllhost', 'conhost', 'taskhostw', 'sihost', 'RuntimeBroker', 'fontdrvhost', 'spoolsv', 'ctfmon', 'audiodg', 'dwm')
$ToolRx = '(?i)^(cheatengine|processhacker|systeminformer|x64dbg|x32dbg|ollydbg|extremeinjector|xenos|injector|dnspy|reclass|autohotkey|autoclick|tinytask|jitbit)'
foreach ($pr in $procs) {
    $pn = $pr.Name
    if (-not $pn) { continue }
    $base = [IO.Path]::GetFileNameWithoutExtension($pn)
    $pp = [string]$pr.ExecutablePath
    $isJava = ($pn -ieq 'javaw.exe' -or $pn -ieq 'java.exe')
    if (-not $isJava -and $pp -match '(?i)^[A-Za-z]:\Windows\' -and -not ($SysNames -contains $base)) { continue }
    $sc = 0
    $why = New-Object System.Collections.Generic.List[string]
    if ($pp -and ($SysNames -contains $base) -and ($pp -notmatch '(?i)^[A-Za-z]:\Windows\')) {
        $sc += 65; [void]$why.Add('sistem process ismi taklidi (dogru klasorde degil)')
    }
    $hit = Get-NameHit $pn $true
    if ($hit) { $ns = Name-Score $hit $true; if ($ns -gt 0) { $sc += $ns; [void]$why.Add('isim eslesmesi: ' + $hit.Name) } }
    if ($base -match $ToolRx) { $sc += 40; [void]$why.Add('hile/enjeksiyon/makro araci ismi') }
    if ($pp -and ($pp -match '(?i)\\Users\\[^\\]+\\(Downloads|Desktop|Documents)\\|\\Temp\\|\\Users\\Public\\')) {
        $sc += 25; [void]$why.Add('kullanici/temp klasorunden calisiyor')
        if (-not (Test-Signed $pp)) { $sc += 15; [void]$why.Add('imzasiz') }
    }
    if ($sc -ge 20) {
        Add-F -Kaynak 'Calisan process' -Ad $pn.ToLower() -Yol $pp -Skor ([Math]::Min(100, $sc)) -Son $pr.CreationDate -Var 'Evet' -Not (($why -join '; ') + ' | PID ' + $pr.ProcessId)
    }
    if ($isJava) {
        $cl = [string]$pr.CommandLine
        $gd = ''
        if ($cl -match '--gameDir\s+(?:"([^"]+)"|(\S+))') { $gd = $Matches[1]; if (-not $gd) { $gd = $Matches[2] } }
        if ($gd) { [void]$script:GameDirs.Add($gd) }
        [void]$script:JavaInfo.Add(('Java PID ' + $pr.ProcessId + ' (basladi: ' + (Fmt $pr.CreationDate) + ') oyun klasoru: ' + $(if ($gd) { $gd } else { 'bilinmiyor' })))
        foreach ($am in [regex]::Matches($cl, '-javaagent:(?:"([^"]+)"|([^\s"]+))')) {
            $ap = $am.Groups[1].Value
            if (-not $ap) { $ap = $am.Groups[2].Value }
            $eq = $ap.IndexOf('=')
            if ($eq -gt 0) { $ap = $ap.Substring(0, $eq) }
            $asc = 30
            $anote = '-javaagent ile yuklenmis (oyuna dis kod yukler; Lunar/Badlion gibi launcher''lar da kullanir)'
            $ah = Get-NameHit $ap $false
            if ($ah) { $asc += 35; $anote = $anote + ' | isim: ' + $ah.Name }
            $api = Test-PathInfo $ap
            $avar = 'Hayir'
            if ($api.Exists) { $avar = 'Evet' }
            Add-F -Kaynak 'Java komut satiri' -Ad ('javaagent: ' + (Split-Path -Leaf $ap).ToLower()) -Yol $ap -Skor $asc -Son $pr.CreationDate -Var $avar -Not $anote
        }
        foreach ($fl in @('-Xbootclasspath', '-agentpath', '-agentlib', '-noverify', '-Xverify:none', '-Djdk.attach.allowAttachSelf')) {
            if ($cl.IndexOf($fl, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                Add-F -Kaynak 'Java komut satiri' -Ad ('javaparam: ' + $fl) -Yol ('PID ' + $pr.ProcessId) -Skor 35 -Son $pr.CreationDate -Var 'Evet' -Not ('Java baslatma parametresi: ' + $fl + ' (dogrulamayi atlar / dis kod yukler)')
            }
        }
        try {
            $gp = Get-Process -Id $pr.ProcessId -ErrorAction Stop
            foreach ($mod in $gp.Modules) {
                $mp2 = $mod.FileName
                if ($mp2 -match '(?i)^[A-Za-z]:\\Windows\\|\\Program Files') { continue }
                $mh = Get-NameHit $mod.ModuleName $false
                $mz = Get-Zone $mp2
                $bad = $false
                $why2 = ''
                if ($mh) {
                    $bad = $true; $why2 = 'isim: ' + $mh.Name
                } elseif (($mz -eq 'user' -or $mz -eq 'shared' -or $mz -eq 'other') -and ($mp2 -notmatch '(?i)\\\.minecraft\\|ModrinthApp|PrismLauncher|\.lunarclient|\\runtime\\|\\jre|\\jdk|\\java') -and -not (Test-Signed $mp2)) {
                    $bad = $true; $why2 = 'imzasiz modul, olagan disi yerde'
                }
                if ($bad) {
                    Add-F -Kaynak 'Java modulu (injection)' -Ad $mod.ModuleName.ToLower() -Yol $mp2 -Skor 65 -Son $pr.CreationDate -Var 'Evet' -Not ('calisan Java icine yuklenmis DLL: ' + $why2)
                }
            }
        } catch {}
    }
}
if ($script:HkOk) {
    $OverlayOk = @('explorer', 'dwm', 'TextInputHost', 'ShellExperienceHost', 'SearchHost', 'SearchApp', 'StartMenuExperienceHost', 'ApplicationFrameHost', 'NVIDIA Overlay', 'nvcontainer', 'NVIDIA Share', 'RTSS', 'MSIAfterburner', 'Discord', 'steamwebhelper', 'steam', 'GameBar', 'XboxGameBar', 'GameBarPresenceWriter', 'obs64', 'Medal', 'Overwolf', 'OverwolfBrowser', 'RadeonSoftware', 'AMDRSSrcExt', 'LockApp', 'ScreenClippingHost', 'SnippingTool', 'PowerToys', 'Lightshot', 'Rainmeter', 'ShareX')
    try {
        foreach ($o in [HkNative]::Overlays()) {
            $parts = $o.Split('|')
            $opid = [int]$parts[0]
            $pname = ''
            try { $pname = (Get-Process -Id $opid -ErrorAction Stop).ProcessName } catch {}
            if ($pname -and ($OverlayOk -notcontains $pname)) {
                $opath = ''
                try { $opath = (Get-Process -Id $opid -ErrorAction Stop).Path } catch {}
                Add-F -Kaynak 'Overlay penceresi' -Ad ('overlay: ' + $pname.ToLower()) -Yol $opath -Skor 40 -Var 'Evet' -Not ('saydam + hep ustte + tiklamayi gecirgen pencere (harici ESP/overlay olabilir). Baslik: ' + $parts[1] + ' boyut: ' + $parts[2])
            }
        }
    } catch {}
}
Show-Section

# ---------------------------------------------------------------------
Step '[4/16] Prefetch: calistirilan programlar ve calisma saatleri...'
Start-Sec
$pfCount = 0
foreach ($pf in $pfFiles) {
    try {
        $info = Read-Prefetch $pf.FullName
        $exe = $info.Exe
        if (-not $exe) { $exe = ($pf.BaseName -split '-')[0] }
        $pathFull = $null
        foreach ($sp in $info.Paths) { if ($sp -like ('*\' + $exe)) { $pathFull = $sp; break } }
        $last = $pf.LastWriteTime
        $runsTxt = ''
        if ($info.Runs.Count -gt 0) {
            $sorted = @($info.Runs | Sort-Object -Descending)
            $last = $sorted[0]
            $runsTxt = 'Prefetch calisma saatleri: ' + ((@($sorted | Select-Object -First 8) | ForEach-Object { Fmt $_ }) -join ', ')
        }
        $pfCount++
        if ($exe -ieq 'WMIC.EXE') {
            Add-Sys 'WMIC.EXE calistirilmis (Prefetch)' 20 'wmic ile exe/uzantisiz dosya/ADS baslatmak hilelerde kullanilir; wmic artik cok nadir kullanildigi icin suphe uyandirabilir.' $last $runsTxt $null
        }
        if ($pathFull) {
            $rr = Resolve-PfPath $pathFull
            Eval-Exec -Kaynak 'Prefetch' -Path $rr.Path -Exists $rr.Exists -Removed $rr.Removed -Last $last -First $pf.CreationTime -Note $runsTxt
        } else {
            Eval-Exec -Kaynak 'Prefetch' -Path $exe -Last $last -First $pf.CreationTime -Note $runsTxt -NoLoc
        }
    } catch {}
}
Log ('   ' + $pfCount + ' Prefetch kaydi incelendi.') 'DarkGray'
Show-Section

# ---------------------------------------------------------------------
Step '[5/16] BAM: programlarin son calistirma zamani (kayit defteri)...'
Start-Sec
$bamCount = 0
foreach ($root in @('HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings', 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings')) {
    if (-not (Test-Path $root)) { continue }
    foreach ($sk in @(Get-ChildItem $root)) {
        foreach ($vn in $sk.GetValueNames()) {
            if ($vn -notmatch '^\\Device\\|^[A-Za-z]:\\') { continue }
            $bytes = $sk.GetValue($vn)
            $t = $null
            if ($bytes -is [byte[]] -and $bytes.Length -ge 8) { $t = Ft ([BitConverter]::ToInt64($bytes, 0)) }
            $rp = Resolve-NtPath $vn
            Eval-Exec -Kaynak 'BAM' -Path $rp.Path -Exists $rp.Exists -Removed $rp.Removed -Last $t -Note 'BAM son calistirma kaydi'
            $bamCount++
        }
    }
}
Log ('   ' + $bamCount + ' BAM kaydi incelendi.') 'DarkGray'
Show-Section

# ---------------------------------------------------------------------
Step '[6/16] UserAssist: calistirma sayisi ve zamani...'
Start-Sec
$KnownFolders = @{
    '{374DE290-123F-4565-9164-39C4925E467B}' = ($UP + '\Downloads')
    '{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}' = ($UP + '\Desktop')
    '{FDD39AD0-238F-46AF-ADB4-6C85480369C7}' = ($UP + '\Documents')
    '{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}' = $env:APPDATA
    '{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}' = $env:LOCALAPPDATA
    '{5E6C858F-0E22-4760-9AFE-EA3317B67173}' = $UP
    '{905E63B6-C1BF-494E-B29C-65B732D3D21A}' = 'C:\Program Files'
    '{6D809377-6AF0-444B-8957-A3773F02200E}' = 'C:\Program Files'
    '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}' = 'C:\Program Files (x86)'
    '{F38BF404-1D43-42F2-9305-67DE0B28FC23}' = 'C:\Windows'
    '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}' = 'C:\Windows\System32'
}
$uaCount = 0
$uaRoot = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
foreach ($g in @(Get-ChildItem $uaRoot)) {
    $ck = $g.OpenSubKey('Count')
    if (-not $ck) { continue }
    foreach ($vn in $ck.GetValueNames()) {
        $dec = Rot13 $vn
        if ($dec -notmatch '(?i)\.exe$') { continue }
        foreach ($kf in $KnownFolders.Keys) { if ($dec.StartsWith($kf, [StringComparison]::OrdinalIgnoreCase)) { $dec = $KnownFolders[$kf] + $dec.Substring($kf.Length); break } }
        if ($dec -notmatch '^[A-Za-z]:\\') { continue }
        $bytes = $ck.GetValue($vn)
        $t = $null
        $cnt = ''
        if ($bytes -is [byte[]] -and $bytes.Length -ge 68) {
            $t = Ft ([BitConverter]::ToInt64($bytes, 60))
            $cnt = 'UserAssist calistirma sayisi: ' + [BitConverter]::ToUInt32($bytes, 4)
        }
        $pi = Test-PathInfo $dec
        Eval-Exec -Kaynak 'UserAssist' -Path $dec -Exists $pi.Exists -Removed $pi.Removed -Last $t -Note $cnt
        $uaCount++
    }
}
Log ('   ' + $uaCount + ' UserAssist kaydi incelendi.') 'DarkGray'
Show-Section

# ---------------------------------------------------------------------
Step '[7/16] Amcache: program envanteri (silinmis programlarin izi)...'
$amCount = 0
$amReason = ''
$amDir = Join-Path $env:TEMP ('hk_amc_' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $amDir -Force -ErrorAction SilentlyContinue)
$amSrc = $env:WINDIR + '\appcompat\Programs\Amcache.hve'
$amTmp = Join-Path $amDir 'Amcache.hve'
$copied = $false
try {
    $eo = & esentutl.exe /y /vss $amSrc /d $amTmp 2>&1
    if (Test-Path -LiteralPath $amTmp) { $copied = $true } else { $amReason = 'esentutl: ' + ((($eo | Out-String).Trim()) -replace '\s+', ' ') }
} catch { $amReason = 'esentutl calistirilamadi: ' + $_.Exception.Message }
if (-not $copied) {
    try { Copy-Item -LiteralPath $amSrc -Destination $amTmp -Force -ErrorAction Stop; $copied = $true } catch { $amReason = $amReason + ' | dogrudan kopya: ' + $_.Exception.Message }
}
if ($copied) {
    $loaded = $false
    $hkn = 'HK_AMC_' + (Get-Random -Maximum 99999)
    $lo = & reg.exe load ('HKLM\' + $hkn) $amTmp 2>&1
    if ($LASTEXITCODE -eq 0) {
        $loaded = $true
    } else {
        foreach ($lgx in @('.LOG1', '.LOG2')) { & esentutl.exe /y /vss ($amSrc + $lgx) /d ($amTmp + $lgx) 2>&1 | Out-Null }
        $lo = & reg.exe load ('HKLM\' + $hkn) $amTmp 2>&1
        if ($LASTEXITCODE -eq 0) { $loaded = $true } else { $amReason = 'hive yuklenemedi: ' + ((($lo | Out-String).Trim()) -replace '\s+', ' ') }
    }
    if ($loaded) {
        Start-Sec
        try {
            $rk = 'Registry::HKEY_LOCAL_MACHINE\' + $hkn + '\Root\InventoryApplicationFile'
            foreach ($k in @(Get-ChildItem -LiteralPath $rk -ErrorAction SilentlyContinue)) {
                $ap = [string]$k.GetValue('LowerCaseLongPath')
                if (-not $ap) { $k.Close(); continue }
                if ($ap -match '(?i)^[a-z]:\\(windows|program files)') { $k.Close(); continue }
                $kt = Get-KeyTime $k
                $pub = [string]$k.GetValue('Publisher')
                $sha = [string]$k.GetValue('FileId')
                $k.Close()
                $pi = Test-PathInfo $ap
                $nt = 'Amcache kaydi'
                if ($pub) { $nt = $nt + ' | yayinci: ' + $pub } else { $nt = $nt + ' | yayinci yok' }
                if ($sha.Length -gt 4) { $nt = $nt + ' | SHA1: ' + $sha.Substring(4) }
                Eval-Exec -Kaynak 'Amcache' -Path $ap -Exists $pi.Exists -Removed $pi.Removed -First $kt -Note $nt
                $amCount++
            }
        } catch {}
        [gc]::Collect()
        [gc]::WaitForPendingFinalizers()
        Start-Sleep -Milliseconds 300
        & reg.exe unload ('HKLM\' + $hkn) 2>&1 | Out-Null
    }
}
Remove-Item -LiteralPath $amDir -Recurse -Force -ErrorAction SilentlyContinue
if ($amCount -eq 0) {
    if ($amReason.Length -gt 300) { $amReason = $amReason.Substring(0, 300) + '...' }
    if (-not $amReason) { $amReason = 'kayit bulunamadi' }
    Log ('   Amcache okunamadi. Neden: ' + $amReason) 'DarkYellow'
} else {
    Log ('   ' + $amCount + ' Amcache kaydi incelendi.') 'DarkGray'
    Show-Section
}

# ---------------------------------------------------------------------
Step '[8/16] Shimcache (AppCompatCache) yol taramasi...'
Start-Sec
$shCount = 0
try {
    $blob = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' -ErrorAction Stop).AppCompatCache
    if ($blob -is [byte[]]) {
        $seenSh = @{}
        foreach ($off in @(0, 1)) {
            $len = $blob.Length - $off
            $sub = New-Object byte[] $len
            [Array]::Copy($blob, $off, $sub, 0, $len)
            $txt = [Text.Encoding]::Unicode.GetString($sub)
            foreach ($pm in (Find-Paths $txt 'exe|jar|bat|ps1|scr|cmd|vbs')) {
                $lk = $pm.ToLower()
                if ($seenSh.ContainsKey($lk)) { continue }
                $seenSh[$lk] = 1
                $pi = Test-PathInfo $pm
                Eval-Exec -Kaynak 'Shimcache' -Path $pm -Exists $pi.Exists -Removed $pi.Removed -Note 'Shimcache kaydi (zaman bilgisi yok)'
                $shCount++
            }
        }
    }
} catch {}
Log ('   ' + $shCount + ' Shimcache yolu incelendi.') 'DarkGray'
Show-Section

# ---------------------------------------------------------------------
Step '[9/16] Recent (son kullanilanlar) ve Jump List kayitlari...'
Start-Sec
$recentDir = Join-Path $env:APPDATA 'Microsoft\Windows\Recent'
$lnks = @(Get-ChildItem -LiteralPath $recentDir -Filter '*.lnk' -Force -ErrorAction SilentlyContinue)
Log ('   Recent klasorunde ' + $lnks.Count + ' kisayol var.') 'DarkGray'
if ($lnks.Count -lt 5) { Add-Sys 'Recent (Son kullanilanlar) neredeyse bos' 30 'Temizlenmis olabilir (normalde onlarca kayit olur).' }
$wsh = $null
try { $wsh = New-Object -ComObject WScript.Shell } catch {}
foreach ($l in $lnks) {
    $target = ''
    try { if ($wsh) { $target = [string]$wsh.CreateShortcut($l.FullName).TargetPath } } catch {}
    $tExt = ''
    try { $tExt = [IO.Path]::GetExtension($target).ToLower() } catch {}
    $lh = Get-NameHit $l.BaseName $true
    if ([string]::IsNullOrWhiteSpace($target)) {
        if ($lh) { Eval-Exec -Kaynak 'Recent (kisayol)' -Path $l.BaseName -Last $l.LastWriteTime -First $l.CreationTime -Note ('kisayol: ' + $l.Name) -NoLoc }
    } elseif (($IntExt -contains $tExt) -or $lh) {
        $pi = Test-PathInfo $target
        Eval-Exec -Kaynak 'Recent (kisayol)' -Path $target -Exists $pi.Exists -Removed $pi.Removed -Last $l.LastWriteTime -First $l.CreationTime -Note ('kisayol: ' + $l.Name)
    }
}
$jlCount = 0
foreach ($jd in @((Join-Path $recentDir 'AutomaticDestinations'), (Join-Path $recentDir 'CustomDestinations'))) {
    foreach ($jf in @(Get-ChildItem -LiteralPath $jd -File -Force -ErrorAction SilentlyContinue)) {
        try {
            $jb = [IO.File]::ReadAllBytes($jf.FullName)
            $jp = @{}
            foreach ($enc in @([Text.Encoding]::Unicode, [Text.Encoding]::ASCII)) {
                $jt = $enc.GetString($jb)
                foreach ($pm in (Find-Paths $jt 'exe|jar|bat|ps1|scr|zip|rar|7z')) { $jp[$pm] = 1 }
            }
            foreach ($pth in $jp.Keys) {
                $pi = Test-PathInfo $pth
                Eval-Exec -Kaynak 'Jump List' -Path $pth -Exists $pi.Exists -Removed $pi.Removed -Last $jf.LastWriteTime -Note 'Jump List kaydi (zaman = uygulamanin liste dosyasi)'
                $jlCount++
            }
        } catch {}
    }
}
Log ('   ' + $jlCount + ' Jump List yolu incelendi.') 'DarkGray'
Show-Section

# ---------------------------------------------------------------------
Step '[10/16] Dosya taramasi (Downloads, Masaustu, Belgeler, Temp, AppData/Roaming, launcher klasorleri)...'
Start-Sec
Add-Root (Get-DownloadsPath)
Add-Root ([Environment]::GetFolderPath('Desktop'))
Add-Root ([Environment]::GetFolderPath('MyDocuments'))
Add-Root $env:APPDATA
Add-Root $env:TEMP
Add-Root ($env:WINDIR + '\Temp')
foreach ($gd in $script:GameDirs) { Add-Root $gd }
Add-Root ($env:ProgramData + '\Microsoft\Windows\Start Menu\Programs\StartUp')
Add-Root ($env:APPDATA + '\Microsoft\Windows\Start Menu\Programs\Startup')
foreach ($base in @($env:LOCALAPPDATA, $UP, $env:ProgramData, $env:ProgramFiles, ${env:ProgramFiles(x86)}, ($env:SystemDrive + '\'))) {
    if (-not $base) { continue }
    foreach ($d in @(Get-ChildItem -LiteralPath $base -Directory -Force -ErrorAction SilentlyContinue)) {
        if ($d.Name -match $script:LauncherRx -or ($base -eq $UP -and $d.Name -match '(?i)^\.(minecraft|lunarclient|tlauncher|badlion|feather|ichor)')) { Add-Root $d.FullName }
    }
}
foreach ($root in $script:ScanRoots) {
    Log ('   taraniyor: ' + $root) 'DarkGray'
    Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object { Inspect-File $_ }
}
Write-Host ''
Log ('   ' + $script:fileCount + ' dosya incelendi.') 'DarkGray'

# --- Phantom Client: JVM args ile calisan, dosya icermeyen hile. launcher_profiles.json (JavaArgs) + surum/feather json dosyalari taranir ---
$script:PhantomRx = New-Object System.Text.RegularExpressions.Regex ('(?i)phantom[\s._\-]*(client|launcher)')
foreach ($pj in $script:ProfileJsonCand) {
    try {
        $j = Get-Content -LiteralPath $pj.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ($j.profiles) {
            foreach ($prop in $j.profiles.PSObject.Properties) {
                $prof = $prop.Value
                $ja = [string]$prof.javaArgs
                if (-not $ja) { continue }
                $lu = $pj.LastWriteTime
                try { if ($prof.lastUsed) { $lu = [datetime]([string]$prof.lastUsed) } } catch {}
                $ver = [string]$prof.lastVersionId
                $pmx = $script:PhantomRx.Match($ja)
                $h = Get-NameHit $ja $true
                if ($pmx.Success) {
                    Add-F -Kaynak 'launcher_profiles.json (JavaArgs)' -Ad ('javaargs: ' + $pmx.Value.ToLower()) -Yol $pj.FullName -Skor 75 -Son $lu -Var 'Evet' -Not ('profil: ' + $prop.Name + ' | surum/loader: ' + $ver + ' | JavaArgs icinde Phantom Client yaziyor (dosyasiz hile, JVM parametresiyle yuklenir) | JavaArgs: ' + $ja)
                } elseif ($h) {
                    Add-F -Kaynak 'launcher_profiles.json (JavaArgs)' -Ad ('javaargs: ' + $h.Name) -Yol $pj.FullName -Skor 55 -Son $lu -Var 'Evet' -Not ('profil: ' + $prop.Name + ' | surum/loader: ' + $ver + ' | JavaArgs icinde hile ismi geciyor (dosyasiz/fileless hile olabilir) | JavaArgs: ' + $ja)
                } elseif ($ja -match '(?i)-javaagent|-Xbootclasspath|-agentpath|-noverify|-Xverify:none') {
                    Add-F -Kaynak 'launcher_profiles.json (JavaArgs)' -Ad ('javaargs: ozel parametre (' + $prop.Name + ')') -Yol $pj.FullName -Skor 35 -Son $lu -Var 'Evet' -Not ('profil: ' + $prop.Name + ' | surum/loader: ' + $ver + ' | dis kod yukleyen JVM parametresi | JavaArgs: ' + $ja)
                }
            }
        }
    } catch {}
}
# Oyuncunun kullandigi surumun (loader) json dosyasi ve Feather klasoru: Phantom Client yazisi aranir
foreach ($jf in $script:JsonCand2) {
    try {
        $jt = [IO.File]::ReadAllText($jf.FullName)
        $jm = $script:PhantomRx.Match($jt)
        if ($jm.Success) {
            $a0 = [Math]::Max(0, $jm.Index - 60)
            $l0 = [Math]::Min(180, $jt.Length - $a0)
            $ctx = ($jt.Substring($a0, $l0) -replace '\s+', ' ')
            Add-F -Kaynak 'Surum/Feather json (JVM args)' -Ad ('json: ' + $jm.Value.ToLower()) -Yol $jf.FullName -Skor 65 -Son $jf.LastWriteTime -Ilk $jf.CreationTime -Var 'Evet' -Not ('Phantom Client yazisi bulundu | baglam: ' + $ctx)
        }
    } catch {}
}

# --- Run / RunOnce kayit defteri: bilgisayar acilista otomatik calisan programlar ve komutlar ---
foreach ($runKey in @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
)) {
    try {
        $rkItem = Get-Item -LiteralPath $runKey -ErrorAction Stop
        $rkTime = Get-KeyTime $rkItem
        $rkNote = ''
        if ($rkTime) { $rkNote = ' | Run anahtari son degisim: ' + (Fmt $rkTime) }
        foreach ($rn in $rkItem.GetValueNames()) {
            if (-not $rn) { continue }
            $cmdline = [string]$rkItem.GetValue($rn)
            if (-not $cmdline) { continue }
            $cmdX = [Environment]::ExpandEnvironmentVariables($cmdline)
            if ($cmdX -match $script:FlRx2) {
                Add-F -Kaynak 'Run (otomatik baslatma)' -Ad ('run: ' + $rn.ToLower()) -Yol $cmdX -Skor 55 -Var 'Evet' -Not ('acilista calisan komutta fileless/script kalibi var | anahtar: ' + $runKey + ' | tam komut: ' + $cmdline + $rkNote)
            }
            $runPaths = New-Object System.Collections.Generic.List[string]
            if ($cmdX -match '(?i)^\s*"([^"]+)"') { [void]$runPaths.Add($Matches[1]) } elseif ($cmdX -match '(?i)^\s*([A-Za-z]:\\.*?\.(?:exe|bat|cmd|ps1|vbs|jar|scr|com))') { [void]$runPaths.Add($Matches[1]) }
            foreach ($rp2 in (Find-Paths $cmdX 'exe|bat|cmd|ps1|vbs|jar|dll|scr')) { [void]$runPaths.Add($rp2) }
            $seenRun = @{}
            foreach ($ep in $runPaths) {
                if ($ep -notmatch '^[A-Za-z]:\\') { continue }
                $ek = $ep.ToLower()
                if ($seenRun.ContainsKey($ek)) { continue }
                $seenRun[$ek] = 1
                $pi = Test-PathInfo $ep
                Eval-Exec -Kaynak 'Run (otomatik baslatma)' -Path $ep -Exists $pi.Exists -Removed $pi.Removed -Note ('kayit adi: ' + $rn + ' | tam komut: ' + $cmdline + $rkNote)
            }
        }
    } catch {}
}

# --- XML Startup kayitlari (C:\Windows\System32\WDI\LogFiles\StartupInfo) ---
$xmlDir = $env:WINDIR + '\System32\WDI\LogFiles\StartupInfo'
if (Test-Path -LiteralPath $xmlDir) {
    $xmlList = @(Get-ChildItem -LiteralPath $xmlDir -Filter '*.xml' -File -Force -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 40)
    $xmlSeen = @{}
    foreach ($xf in $xmlList) {
        try {
            $xb = [IO.File]::ReadAllBytes($xf.FullName)
            foreach ($pth in (Get-PathsFromBytes $xb $true)) {
                $lk = $pth.ToLower()
                if ($xmlSeen.ContainsKey($lk)) { continue }
                $xmlSeen[$lk] = 1
                if ($pth -match '^[A-Za-z]:\\') {
                    $pi = Test-PathInfo $pth
                    Eval-Exec -Kaynak 'XML Startup (boot izleme)' -Path $pth -Exists $pi.Exists -Removed $pi.Removed -Last $xf.LastWriteTime -Note ('acilis kaydi: ' + $xf.Name)
                } else {
                    $h = Get-NameHit $pth $false
                    if ($h) {
                        Add-F -Kaynak 'XML Startup (boot izleme)' -Ad $lk -Yol $pth -Skor 45 -Son $xf.LastWriteTime -Var 'Bilinmiyor' -Not ('acilista calisan program olarak kaydedilmis, hile ismi: ' + $h.Name + ' | dosya: ' + $xf.Name)
                    }
                }
            }
        } catch {}
    }
    Log ('   ' + $xmlList.Count + ' XML Startup dosyasi incelendi.') 'DarkGray'
}

# --- PowerShell gecmisi ve olay loglari: fileless (dosyasiz) calistirma izleri ---
# Anahtar kelimeler: "Invoke-" ve "System.Reflection.Assembly". Tek basina BAN sebebi degildir, sadece suphe uyandirir;
# bulunan komutun tamamina bakip icinde bir dosya veya web sitesi var mi kontrol etmek gerekir.
$flRx = '(?i)Invoke-|System\.Reflection\.Assembly'
$flStrong = '(?i)((Invoke-Expression|\bIEX\b)[^\r\n]*(https?://|DownloadString|Invoke-RestMethod|Invoke-WebRequest))|((Invoke-RestMethod|Invoke-WebRequest|DownloadString)[^\r\n]*(Invoke-Expression|\bIEX\b))|(Reflection\.Assembly\]?::Load)'
$psHist = $env:APPDATA + '\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
if (Test-Path -LiteralPath $psHist) {
    $hcontent = @(Get-Content -LiteralPath $psHist -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch 'HileKiran\.ps1' })
    $hTime = (Get-Item -LiteralPath $psHist).LastWriteTime
    $flHits = @($hcontent | Where-Object { $_ -match $flRx })
    if ($flHits.Count -gt 0) {
        $strongH = @($flHits | Where-Object { $_ -match $flStrong })
        $showH = $flHits
        $skorH = 35
        if ($strongH.Count -gt 0) { $showH = $strongH; $skorH = 55 }
        $samples = @($showH | Select-Object -First 3 | ForEach-Object { $t2 = ([string]$_).Trim(); if ($t2.Length -gt 220) { $t2 = $t2.Substring(0, 220) + '...' }; $t2 })
        Add-Sys ('PowerShell gecmisinde fileless calistirma izi (' + $flHits.Count + ' satir)') $skorH 'Invoke-* / System.Reflection.Assembly komutlari dosyasiz (bellekten) kod calistirmak icin kullanilabilir; her zaman kotu amacli degildir. Komutun tamamina bak: icinde bir dosya veya web sitesi var mi?' $null ($samples -join ' || ') $hTime
    }
    $wmH = @($hcontent | Where-Object { $_ -match '(?i)wmic(\.exe)?\s+.*process\s+call\s+create' })
    if ($wmH.Count -gt 0) {
        Add-Sys ('PowerShell gecmisinde wmic ile program baslatma (' + $wmH.Count + ' satir)') 45 'wmic ... process call create komutu bir exe/uzantisiz dosya/ADS baslatmak icin hilelerde kullanilir.' $null (([string]$wmH[0]).Trim()) $hTime
    }
}
foreach ($evId in @(4104, 4103)) {
    try {
        $evs = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = $evId } -MaxEvents 300 -ErrorAction Stop | Where-Object { $_.ProcessId -ne $PID -and $_.Message -notmatch 'HileKiran\.ps1' })
        $flEvt = @($evs | Where-Object { $_.Message -match $flRx })
        if ($flEvt.Count -gt 0) {
            $strongE = @($flEvt | Where-Object { $_.Message -match $flStrong })
            $skorE = 35
            $firstE = $flEvt[0]
            if ($strongE.Count -gt 0) { $skorE = 55; $firstE = $strongE[0] }
            $mline = [string]($firstE.Message -split "`n" | Where-Object { $_ -match $flRx } | Select-Object -First 1)
            $mline = $mline.Trim()
            if ($mline.Length -gt 220) { $mline = $mline.Substring(0, 220) + '...' }
            Add-Sys ('PowerShell olay logunda (olay ' + $evId + ') fileless calistirma izi (' + $flEvt.Count + ' kayit)') $skorE 'Calistirilan PowerShell komut/script bloklarinda Invoke-* / System.Reflection.Assembly kaliplari bulundu. Tam komuta bak.' $firstE.TimeCreated $mline $firstE.TimeCreated
        }
    } catch {}
}
Show-Section

# ---------------------------------------------------------------------
Step '[11/16] Gorev Zamanlayici (Task Scheduler), WMI abonelikleri, StartUp klasoru...'
Start-Sec
$taskRoot2 = $env:WINDIR + '\System32\Tasks'
$taskFiles = @{}
$taskCount = 0
if (Test-Path -LiteralPath $taskRoot2) {
    foreach ($tf in @(Get-ChildItem -LiteralPath $taskRoot2 -Recurse -File -Force -ErrorAction SilentlyContinue)) {
        $rel = $tf.FullName.Substring($taskRoot2.Length)
        $taskFiles[$rel.ToLower()] = $tf
        $xml = $null
        try { $xml = [xml](Get-Content -LiteralPath $tf.FullName -Raw -ErrorAction Stop) } catch {}
        if (-not $xml -or -not $xml.Task) { continue }
        $taskCount++
        $isMs = ($rel -match '(?i)^\\Microsoft\\')
        $trig = ''
        try { if ($xml.Task.Triggers) { $trig = (@($xml.Task.Triggers.ChildNodes | ForEach-Object { $_.LocalName }) -join ',') } } catch {}
        $regDate = $null
        try { $regDate = [datetime]([string]$xml.Task.RegistrationInfo.Date) } catch {}
        foreach ($ex in @($xml.Task.Actions.Exec)) {
            if (-not $ex) { continue }
            $cmd = [string]$ex.Command
            if (-not $cmd) { continue }
            $targ = [string]$ex.Arguments
            $targX = [Environment]::ExpandEnvironmentVariables($targ)
            $cmdX = [Environment]::ExpandEnvironmentVariables($cmd).Trim().Trim('"')
            $full = $cmdX + ' ' + $targX
            $hit = Get-NameHit $full $false
            if ($isMs -and -not $hit) { continue }
            $sc = 0
            $why = New-Object System.Collections.Generic.List[string]
            if ($hit) { $sc += 45; [void]$why.Add('isim eslesmesi: ' + $hit.Name) }
            if ($full -match $script:FlRx2) { $sc += 40; [void]$why.Add('fileless/script kalibi (Invoke-/Reflection/base64/gizli pencere vb.)') }
            if ($full -match '(?i)https?://') { $sc += 15; [void]$why.Add('komutta web adresi var') }
            if ($cmdX -match '^[A-Za-z]:\\') {
                $cmdExists = [bool](Test-Path -LiteralPath $cmdX)
                $zc = Get-Zone $cmdX
                if (-not $cmdExists) {
                    $sc += 30; [void]$why.Add('gorevin komut dosyasi SILINMIS/yok')
                } elseif ($zc -eq 'user' -or $zc -eq 'temp' -or $zc -eq 'appdata' -or $zc -eq 'shared') {
                    $sc += 20; [void]$why.Add('gorev kullanici/temp/AppData klasorundeki bir programi calistiriyor')
                }
            }
            if (($trig -match '(?i)Boot|Logon') -and $sc -gt 0) { $sc += 10; [void]$why.Add('tetikleyici: ' + $trig) }
            if ($sc -ge 15) {
                $nt = ($why -join '; ') + ' | komut: ' + $cmd + ' | arguman: ' + $targ
                Add-F -Kaynak 'Gorev Zamanlayici' -Ad ('gorev: ' + $tf.Name.ToLower()) -Yol ($rel + '  ->  ' + $cmd) -Skor ([Math]::Min(100, $sc)) -Son $tf.LastWriteTime -Ilk $regDate -Var 'Evet' -Not $nt
            }
            foreach ($ap in (Find-Paths $targX 'exe|dll|jar|bat|ps1|cmd|vbs|scr')) {
                $api = Test-PathInfo $ap
                Eval-Exec -Kaynak 'Gorev Zamanlayici (arguman)' -Path $ap -Exists $api.Exists -Removed $api.Removed -Last $tf.LastWriteTime -Note ('gorev: ' + $rel)
            }
        }
    }
}
Log ('   ' + $taskCount + ' zamanlanmis gorev incelendi.') 'DarkGray'

# Gorev kayit defteri (TaskCache) ile Tasks klasoru birbirini tutuyor mu? (gizlenmis/silinmis gorev izi)
$taskTreeSet = @{}
try {
    $trBase = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'
    $trLen = ('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree').Length
    foreach ($k in @(Get-ChildItem -LiteralPath $trBase -Recurse -ErrorAction SilentlyContinue)) {
        $tid = $k.GetValue('Id')
        if (-not $tid) { $k.Close(); continue }
        $krel = $k.Name.Substring($trLen)
        $taskTreeSet[$krel.ToLower()] = 1
        $ktime = Get-KeyTime $k
        $k.Close()
        if ($taskFiles.Count -gt 0 -and -not $taskFiles.ContainsKey($krel.ToLower())) {
            Add-Sys ('Gorev kayit defterinde var ama dosyasi YOK: ' + $krel) 40 'Gorev Zamanlayici kaydi duruyor ama System32\Tasks icindeki dosyasi silinmis; gorev gizlenmis veya iz silinmis olabilir.' $null ('Id=' + $tid) $ktime
        }
    }
} catch {}
if ($taskTreeSet.Count -gt 0) {
    foreach ($fk in @($taskFiles.Keys)) {
        if (-not $taskTreeSet.ContainsKey($fk)) {
            $tfo = $taskFiles[$fk]
            Add-Sys ('Gorev dosyasi var ama kayit defterinde YOK: ' + $fk) 30 'System32\Tasks icinde dosya var ama TaskCache kaydi yok; Gorev Zamanlayici arayuzunde gorunmeyen gorev olabilir.' $null ('dosya: ' + $tfo.FullName) $tfo.LastWriteTime
        }
    }
}
# Silinen gorevler: olay gunlugu aciksa (Windows varsayilani kapali) silinme zamanlari buradan gelir
try {
    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; Id = 141 } -MaxEvents 15 -ErrorAction Stop)) {
        $qm = [regex]::Matches([string]$e.Message, '"([^"]+)"')
        $tn = [string]$e.Message
        if ($qm.Count -gt 0) { $tn = $qm[$qm.Count - 1].Groups[1].Value }
        Add-Sys ('Gorev SILINMIS (olay 141): ' + $tn) 30 'Gorev Zamanlayici olay gunlugu: bu gorev silinmis.' $e.TimeCreated $null $e.TimeCreated
    }
} catch {}
try {
    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4699 } -MaxEvents 15 -ErrorAction Stop)) {
        $tn = ''
        try { $tn = [string]$e.Properties[4].Value } catch {}
        Add-Sys ('Gorev SILINMIS (guvenlik olayi 4699): ' + $tn) 30 'Guvenlik olay gunlugu: bir zamanlanmis gorev silinmis.' $e.TimeCreated $null $e.TimeCreated
    }
} catch {}
# WMI kalici olay aboneligi (kalici baslatma yontemi)
try {
    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-WMI-Activity/Operational'; Id = 5861 } -MaxEvents 10 -ErrorAction Stop)) {
        $wmsg = ([string]$e.Message -replace '\s+', ' ')
        if ($wmsg.Length -gt 220) { $wmsg = $wmsg.Substring(0, 220) + '...' }
        Add-Sys 'WMI kalici olay aboneligi olusturulmus (olay 5861)' 35 'WMI uzerinden kalici tetikleyici/komut tanimlanmis; hile veya zararli yazilim kalici calismak icin kullanabilir.' $e.TimeCreated $wmsg $e.TimeCreated
    }
} catch {}

# --- Start Menu\Programs\StartUp klasorleri: bilgisayar acilinca calisan kisayol/script/exe ---
$wsh2 = $null
try { $wsh2 = New-Object -ComObject WScript.Shell } catch {}
$suCount = 0
$scriptExt = @('.py', '.pyw', '.ps1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.html', '.htm', '.hta', '.jar', '.exe', '.dll', '.scr', '.com', '.url')
foreach ($sd in @(($env:ProgramData + '\Microsoft\Windows\Start Menu\Programs\StartUp'), ($env:APPDATA + '\Microsoft\Windows\Start Menu\Programs\Startup'))) {
    if (-not (Test-Path -LiteralPath $sd)) { continue }
    foreach ($sf in @(Get-ChildItem -LiteralPath $sd -File -Force -ErrorAction SilentlyContinue)) {
        if ($sf.Name -ieq 'desktop.ini') { continue }
        $suCount++
        $sext = $sf.Extension.ToLower()
        $sc = 0
        $why = New-Object System.Collections.Generic.List[string]
        $hit = Get-NameHit $sf.Name $false
        if ($hit) { $sc += 45; [void]$why.Add('dosya adi: ' + $hit.Name) }
        if ($sext -eq '.lnk') {
            $tg = ''
            $ta = ''
            try { if ($wsh2) { $lk = $wsh2.CreateShortcut($sf.FullName); $tg = [string]$lk.TargetPath; $ta = [string]$lk.Arguments } } catch {}
            $lh = Get-NameHit ($tg + ' ' + $ta) $false
            if ($lh) { $sc += 40; [void]$why.Add('kisayol hedefinde isim: ' + $lh.Name) }
            if (($tg + ' ' + $ta) -match $script:FlRx2) { $sc += 40; [void]$why.Add('kisayol komutunda fileless/script kalibi') }
            if ($tg -match '^[A-Za-z]:\\') {
                $tpi = Test-PathInfo $tg
                Eval-Exec -Kaynak 'StartUp klasoru (kisayol)' -Path $tg -Exists $tpi.Exists -Removed $tpi.Removed -Last $sf.LastWriteTime -First $sf.CreationTime -Note ('kisayol: ' + $sf.Name + ' | arguman: ' + $ta)
            }
            if ($sc -gt 0) { [void]$why.Add('hedef: ' + $tg + ' ' + $ta) }
        } elseif ($scriptExt -contains $sext) {
            $sc += 30
            [void]$why.Add('StartUp klasorunde ' + $sext + ' dosyasi var (normalde sadece kisayol bulunur)')
            if (@('.html', '.htm', '.hta') -contains $sext) { $sc += 15 }
            if ($sf.Length -lt 2097152 -and (@('.exe', '.dll', '.scr', '.com', '.jar') -notcontains $sext)) {
                $ctext = ''
                try { $ctext = [IO.File]::ReadAllText($sf.FullName) } catch {}
                if ($ctext) {
                    $ch = Get-NameHit $ctext $false
                    if ($ch) { $sc += 30; [void]$why.Add('icerikte hile ismi: ' + $ch.Name) }
                    if ($ctext -match $script:FlRx2) { $sc += 25; [void]$why.Add('icerikte fileless/script kalibi') }
                    if ($ctext -match '(?i)https?://') { $sc += 10; [void]$why.Add('icerikte web adresi var') }
                }
            }
            if ($sext -eq '.exe' -and -not (Test-Signed $sf.FullName)) { $sc += 20; [void]$why.Add('imzasiz exe') }
        }
        if ($sc -ge 10) {
            Add-F -Kaynak 'StartUp klasoru' -Ad $sf.Name.ToLower() -Yol $sf.FullName -Skor ([Math]::Min(100, $sc)) -Son $sf.LastWriteTime -Ilk $sf.CreationTime -Var 'Evet' -Not ($why -join '; ')
        }
    }
}
Log ('   StartUp klasorlerinde ' + $suCount + ' oge incelendi.') 'DarkGray'
Show-Section

# ---------------------------------------------------------------------
Step '[12/16] Kayit defteri izleri (OpenSavePidlMRU, MountedDevices, VolumeInfoCache, DirectInput, WordWheelQuery, Uyumluluk, WinRAR, MuiCache)...'
Start-Sec
# --- Dosya Ac/Kaydet diyalogu gecmisi: OpenSavePidlMRU (uzantilar + dosya adlari), LastVisitedPidlMRU (diyalogu acan programlar) ---
$mruBase = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32'
$extFound = New-Object System.Collections.Generic.List[string]
$extTime = $null
foreach ($mk in @('OpenSavePidlMRU', 'LastVisitedPidlMRU')) {
    $rb = $mruBase + '\' + $mk
    if (-not (Test-Path -LiteralPath $rb)) { continue }
    $nodes = New-Object System.Collections.Generic.List[object]
    try { [void]$nodes.Add((Get-Item -LiteralPath $rb -ErrorAction Stop)) } catch {}
    foreach ($chd in @(Get-ChildItem -LiteralPath $rb -ErrorAction SilentlyContinue)) {
        [void]$nodes.Add($chd)
        if ($mk -eq 'OpenSavePidlMRU') {
            $en = $chd.PSChildName.ToLower()
            if (@('jar', 'exe', 'dll', 'bat', 'cmd', 'ps1', 'vbs', 'scr', 'zip', 'rar', '7z', 'py', 'msi') -contains $en) {
                [void]$extFound.Add($en)
                $ktE = Get-KeyTime $chd
                if ($ktE -and (-not $extTime -or $ktE -gt $extTime)) { $extTime = $ktE }
            }
        }
    }
    foreach ($nd in $nodes) {
        $kt = Get-KeyTime $nd
        foreach ($vn in $nd.GetValueNames()) {
            if ($vn -eq 'MRUListEx' -or -not $vn) { continue }
            $vb = $nd.GetValue($vn)
            if ($vb -isnot [byte[]]) { continue }
            foreach ($pth in (Get-PathsFromBytes $vb $true)) {
                if ($pth -match '^[A-Za-z]:\\') {
                    $pi = Test-PathInfo $pth
                    Eval-Exec -Kaynak ('ComDlg32\' + $mk) -Path $pth -Exists $pi.Exists -Removed $pi.Removed -Last $kt -Note 'Dosya Ac/Kaydet diyalogu gecmisi'
                } else {
                    Eval-Exec -Kaynak ('ComDlg32\' + $mk) -Path $pth -Last $kt -Note 'Dosya Ac/Kaydet diyalogu gecmisi (sadece dosya adi)' -NoLoc
                }
            }
        }
    }
}
if ($extFound.Count -gt 0) {
    $extList = (@($extFound | Select-Object -Unique) -join ', ')
    $extSkor = 8
    if (@($extFound) -contains 'jar' -or @($extFound) -contains 'exe' -or @($extFound) -contains 'dll') { $extSkor = 15 }
    Add-Sys 'Dosya Ac/Kaydet diyalogunda kod/arsiv uzantilari kullanilmis (OpenSavePidlMRU)' $extSkor 'Bu uzantilarla bir dosya acilmis/kaydedilmis. Ayrintili dosya adlari asagidaki bulgularda (varsa) listelenir.' $null ('uzantilar: ' + $extList) $extTime
}

# --- MountedDevices: harfi olup su an takili olmayan surucular, harf atanmamis (\??\Volume) hacimler ---
try {
    $md = Get-Item -LiteralPath 'HKLM:\SYSTEM\MountedDevices' -ErrorAction Stop
    $mdKt = Get-KeyTime $md
    $volOnly = 0
    $mdShown = 0
    foreach ($vn in $md.GetValueNames()) {
        if ($vn -match '^\\DosDevices\\([A-Za-z]:)$') {
            $dl = $Matches[1].ToUpper()
            if ($script:Drives -contains $dl) { continue }
            $desc = 'disk imzasi (sabit disk/bolum kaydi)'
            $bytes = $md.GetValue($vn)
            if ($bytes -is [byte[]] -and $bytes.Length -ge 8) {
                $tx = ([Text.Encoding]::Unicode.GetString($bytes)).TrimEnd([char]0)
                if ($tx -match '^_\?\?_') { $desc = $tx }
            }
            $mdShown++
            if ($mdShown -le 10) { Add-Sys ('Kayitli ama su an takili olmayan surucu harfi: ' + $dl) 15 'MountedDevices kaydinda var, simdi takili degil (cikarilmis USB/disk olabilir).' $null $desc $mdKt }
        } elseif ($vn -match '^\\\?\?\\Volume\{') {
            $volOnly++
        }
    }
    if ($volOnly -gt 0) {
        Add-Sys ('Harf atanmamis hacim kaydi: ' + $volOnly + ' adet (\??\Volume{...})') 10 'Bu kayitlar gizli veya silinmis suruculere ait olabilir (cogu zaman normaldir: kurtarma bolumu, eski USB).' $null $null $mdKt
    }
} catch {}

# --- Windows Search VolumeInfoCache: eskiden kullanilmis surucu harfleri (silinse de kayit kalir) ---
try {
    foreach ($c in @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Search\VolumeInfoCache' -ErrorAction Stop)) {
        $dl = $c.PSChildName.TrimEnd('\').ToUpper()
        $lbl = [string]$c.GetValue('VolumeLabel')
        $dty = $c.GetValue('DriveType')
        $kt = Get-KeyTime $c
        $c.Close()
        if ($dl -match '^[A-Z]:$' -and ($script:Drives -notcontains $dl)) {
            $vs = 15
            if ($dty -eq 2) { $vs = 20 }
            Add-Sys ('Eskiden kullanilmis surucu (su an takili degil): ' + $dl) $vs 'Windows Search VolumeInfoCache: bu harfle bir surucu takilmis (surucu silinse de kayit kalir). Tur 2 = cikarilabilir (USB).' $null ('etiket=' + $lbl + ', surucu turu=' + $dty) $kt
        }
    }
} catch {}

# --- DirectInput: DirectInput kullanan programlar (bazi hileler kullanir) ---
try {
    foreach ($c in @(Get-ChildItem -LiteralPath 'HKCU:\Software\Microsoft\DirectInput' -ErrorAction Stop)) {
        $kn = $c.PSChildName
        $kt = Get-KeyTime $c
        $nameV = [string]$c.GetValue('Name')
        $pathV = [string]$c.GetValue('Path')
        $c.Close()
        $cand = ($kn -replace '[0-9A-Fa-f]{16}$', '')
        if ($nameV) { $cand = $nameV }
        if ($pathV -match '^[A-Za-z]:\\') {
            $pi = Test-PathInfo $pathV
            Eval-Exec -Kaynak 'DirectInput' -Path $pathV -Exists $pi.Exists -Removed $pi.Removed -Last $kt -Note ('DirectInput kaydi: ' + $kn)
        } elseif ($cand) {
            Eval-Exec -Kaynak 'DirectInput' -Path $cand -Last $kt -Note ('DirectInput kaydi: ' + $kn) -NoLoc
        }
    }
} catch {}

# --- WordWheelQuery: Dosya Gezgini sag ustteki arama kutusunun gecmisi ---
try {
    $ww = Get-Item -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery' -ErrorAction Stop
    $wwKt = Get-KeyTime $ww
    foreach ($vn in $ww.GetValueNames()) {
        if ($vn -eq 'MRUListEx' -or -not $vn) { continue }
        $vb = $ww.GetValue($vn)
        if ($vb -isnot [byte[]]) { continue }
        $q = ([Text.Encoding]::Unicode.GetString($vb)).TrimEnd([char]0)
        if (-not $q) { continue }
        $h = Get-NameHit $q $false
        if ($h) {
            Add-F -Kaynak 'Dosya Gezgini arama gecmisi (WordWheelQuery)' -Ad ('arama: ' + $q.ToLower()) -Yol $q -Skor 40 -Son $wwKt -Var 'Bilinmiyor' -Not ('Dosya Gezgini aramasinda hile ismi aranmis: ' + $h.Name + ' | anahtar son degisim: ' + (Fmt $wwKt))
        }
    }
} catch {}

# --- Compatibility Assistant (Store / Persisted): calistirilmis programlarin yollari ---
foreach ($cak in @('Store', 'Persisted')) {
    try {
        $cas = Get-Item -LiteralPath ('HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\' + $cak) -ErrorAction Stop
        foreach ($vn in $cas.GetValueNames()) {
            if ($vn -notmatch '^[A-Za-z]:\\') { continue }
            $pi = Test-PathInfo $vn
            Eval-Exec -Kaynak ('Compatibility Assistant ' + $cak) -Path $vn -Exists $pi.Exists -Removed $pi.Removed -Note 'Uyumluluk yardimcisi kaydi (program calistirilmis)'
        }
    } catch {}
}
# --- WinRAR gecmisi: acilan arsivler ---
try {
    $wr = Get-ItemProperty -LiteralPath 'HKCU:\Software\WinRAR\ArcHistory' -ErrorAction Stop
    foreach ($prop in $wr.PSObject.Properties) {
        if ($prop.Name -match '^PS') { continue }
        $vp = [string]$prop.Value
        if ($vp -notmatch '^[A-Za-z]:\\') { continue }
        $h = Get-NameHit $vp $true
        if ($h) {
            $pi = Test-PathInfo $vp
            $wvar = 'Hayir'
            if ($pi.Exists) { $wvar = 'Evet' }
            Add-F -Kaynak 'WinRAR gecmisi' -Ad (Split-Path -Leaf $vp).ToLower() -Yol $vp -Skor 40 -Var $wvar -Not ('WinRAR ile acilmis arsiv | isim eslesmesi: ' + $h.Name)
        }
    }
} catch {}
# --- MuiCache: calistirilmis programlarin gorunen adlari (deger adi: yol.FriendlyAppName) ---
try {
    $mc = Get-Item -LiteralPath 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache' -ErrorAction Stop
    $mcSeen = @{}
    foreach ($vn in $mc.GetValueNames()) {
        $mp = $vn -replace '\.(FriendlyAppName|ApplicationCompany)$', ''
        if ($mp -notmatch '(?i)^[A-Za-z]:\\.*\.(exe|dll)$') { continue }
        $mk2 = $mp.ToLower()
        if ($mcSeen.ContainsKey($mk2)) { continue }
        $mcSeen[$mk2] = 1
        $pi = Test-PathInfo $mp
        Eval-Exec -Kaynak 'MuiCache' -Path $mp -Exists $pi.Exists -Removed $pi.Removed -Note 'MuiCache kaydi (program en az bir kez calistirilmis)'
    }
} catch {}
Show-Section

# ---------------------------------------------------------------------
Step '[13/16] Bellek (RAM) string taramasi: ctfmon, sihost, explorer, DPS, Dnscache... (birkac dakika surebilir)'
Start-Sec
$script:MemOk = 0
$script:MemFail = 0
$script:MemFailNames = New-Object System.Collections.Generic.List[string]
if (-not $script:HkOk) {
    Log '   yardimci modul derlenemedi, bellek taramasi atlandi.' 'DarkYellow'
} else {
    try { [void][HkNative]::EnableDebug() } catch {}
    $rxExe = '\.(?:exe|dll|jar|bat|ps1|cmd|vbs|scr)'
    $rxDom = '\.(?:com|net|org|gg|io|xyz|ru|to|cc|club|pw|dev|me|app|su|cloud|shop|store|lol|fun|top|info|site|online|space|tech|cx|ws)(?![a-z0-9])'
    $memDone = @{}
    # Normal process'ler: etiket, process adi, regex, mod
    $procTargets = @(
        @('ctfmon', 'ctfmon', $rxExe, 'exe'),
        @('sihost', 'sihost', $rxExe, 'exe'),
        @('taskhostw', 'taskhostw', $rxExe, 'exe'),
        @('explorer', 'explorer', ($rxExe + '|wmic'), 'wmic'),
        @('SearchIndexer', 'SearchIndexer', $rxExe, 'exe'),
        @('SmartScreen', 'smartscreen', $rxExe, 'exe'),
        @('csrss', 'csrss', $rxExe, 'exe'),
        @('SgrmBroker', 'SgrmBroker', 'wmic', 'wmic'),
        @('MsMpEng', 'MsMpEng', 'wmic', 'wmic')
    )
    foreach ($pt in $procTargets) {
        foreach ($gp in @(Get-Process -Name $pt[1] -ErrorAction SilentlyContinue)) {
            $mkey = ([string]$gp.Id) + '|' + $pt[3]
            if ($memDone.ContainsKey($mkey)) { continue }
            $memDone[$mkey] = 1
            Scan-MemProcess $pt[0] $gp.Id $pt[2] $pt[3]
        }
    }
    # Servisler (svchost icinde calisir): servis adi, regex, mod
    $svcTargets = @(
        @('Appinfo', $rxExe, 'exe'),
        @('DPS', $rxExe, 'dps'),
        @('mpssvc', $rxExe, 'exe'),
        @('BFE', $rxExe, 'exe'),
        @('DiagTrack', $rxExe, 'exe'),
        @('SysMain', $rxExe, 'exe'),
        @('Dnscache', $rxDom, 'dns')
    )
    foreach ($st in $svcTargets) {
        $svo = Get-CimInstance Win32_Service -Filter ("Name='" + $st[0] + "'")
        if (-not $svo -or -not $svo.ProcessId -or $svo.ProcessId -le 0) { continue }
        $mkey = ([string]$svo.ProcessId) + '|' + $st[2]
        if ($memDone.ContainsKey($mkey)) { continue }
        $memDone[$mkey] = 1
        Scan-MemProcess $st[0] ([int]$svo.ProcessId) $st[1] $st[2]
    }
    $failTxt = ''
    if ($script:MemFail -gt 0) { $failTxt = ' | okunamayanlar: ' + (($script:MemFailNames | Select-Object -Unique) -join ', ') + ' (korumali/PPL process olabilir)' }
    Log ('   ' + $script:MemOk + ' process bellegi tarandi, ' + $script:MemFail + ' tanesi okunamadi' + $failTxt) 'DarkGray'
}
Show-Section

# ---------------------------------------------------------------------
Step '[14/16] Minecraft loglari (hile modulu isimleri, eski loglar dahil)...'
Start-Sec
$mcMain = $env:APPDATA + '\.minecraft'
if (Test-Path -LiteralPath $mcMain) {
    $lg = $mcMain + '\logs'
    $lgFiles = @()
    if (Test-Path -LiteralPath $lg) { $lgFiles = @(Get-ChildItem -LiteralPath $lg -File -Force -ErrorAction SilentlyContinue) }
    if ($lgFiles.Count -eq 0) { Add-Sys '.minecraft\logs klasoru bos/yok' 25 'Oyun loglari silinmis olabilir (normalde her oturumda log olusur).' }
}
$logs = @($script:LogCand | Sort-Object LastWriteTime -Descending | Select-Object -First 60)
$logHits = 0
foreach ($lf in $logs) {
    $txt = Read-LogText $lf.FullName
    if (-not $txt) { continue }
    $shown = 0
    foreach ($line in $txt.Split("`n")) {
        if ($shown -ge 3) { break }
        $h = Get-NameHit $line $false
        if ($h) {
            $shown++
            $logHits++
            $ln2 = $line.Trim()
            if ($ln2.Length -gt 170) { $ln2 = $ln2.Substring(0, 170) + '...' }
            Add-F -Kaynak 'Minecraft logu' -Ad ('log: ' + $h.Name + ' | ' + $lf.Name.ToLower()) -Yol $lf.FullName -Skor 40 -Son $lf.LastWriteTime -Ilk $lf.CreationTime -Var 'Evet' -Not ('satir: ' + $ln2)
        }
    }
}
Log ('   ' + $logs.Count + ' log dosyasi incelendi.') 'DarkGray'
Show-Section

# ---------------------------------------------------------------------
Step '[15/16] USB depolama gecmisi (harici surucuden calistirma ihtimali)...'
Start-Sec
$setup = @{}
foreach ($sf in @(Get-ChildItem -LiteralPath ($env:WINDIR + '\INF') -Filter 'setupapi.dev*.log' -File -Force -ErrorAction SilentlyContinue | Sort-Object LastWriteTime)) {
    $slines = @(Get-Content -LiteralPath $sf.FullName -ErrorAction SilentlyContinue)
    for ($i = 0; $i -lt ($slines.Count - 1); $i++) {
        if ($slines[$i] -match 'Device Install.*USBSTOR\\(.+?)\]\s*$') {
            $devId = $Matches[1].ToLower()
            if ($slines[$i + 1] -match 'Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})') {
                if (-not $setup.ContainsKey($devId)) { $setup[$devId] = $Matches[1] }
            }
        }
    }
}
foreach ($dev in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -ErrorAction SilentlyContinue)) {
    foreach ($inst in @(Get-ChildItem $dev.PSPath -ErrorAction SilentlyContinue)) {
        $fn = [string]$inst.GetValue('FriendlyName')
        if (-not $fn) { $fn = $dev.PSChildName }
        $key = ($dev.PSChildName + '\' + $inst.PSChildName).ToLower()
        $first = $null
        if ($setup.ContainsKey($key)) { try { $first = [datetime]::ParseExact($setup[$key], 'yyyy/MM/dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) } catch {} }
        [void]$script:UsbList.Add([pscustomobject]@{ Ad = $fn; Ilk = $first; Son = (Get-KeyTime $inst) })
    }
}
Log ('   ' + $script:UsbList.Count + ' USB depolama cihazi kaydi bulundu.') 'DarkGray'
Show-Section

# ---------------------------------------------------------------------
Step '[16/16] Windows Defender tespit gecmisi (silinmis/karantinaya alinmis dosyalar)...'
Start-Sec
$defCount = 0
try {
    foreach ($td in @(Get-MpThreatDetection -ErrorAction Stop)) {
        $tn = ''
        try { $tn = (Get-MpThreat -ThreatID $td.ThreatID -ErrorAction Stop).ThreatName } catch {}
        foreach ($res in @($td.Resources)) {
            if ($res -notmatch '^file:_') { continue }
            $rp = $res -replace '^file:_', ''
            $leaf = ''
            try { $leaf = Split-Path -Leaf $rp } catch {}
            if (-not $leaf) { continue }
            $pi = Test-PathInfo $rp
            $dsc = 40
            if ($tn -match '(?i)hacktool|cheat|inject|gamehack|exploit|trojan|backdoor|pua|riskware') { $dsc = 55 }
            $dvar = 'Hayir'
            if ($pi.Exists) { $dvar = 'Evet' }
            Add-F -Kaynak 'Defender tespiti' -Ad $leaf.ToLower() -Yol $rp -Skor $dsc -Son $td.InitialDetectionTime -Ilk $td.InitialDetectionTime -Var $dvar -Not ('Defender tespit etti: ' + $tn)
            $defCount++
        }
    }
} catch {}
Log ('   ' + $defCount + ' Defender kaydi bulundu.') 'DarkGray'
Show-Section

# =====================================================================
# BIRLESTIRME (ayni dosya adi birden fazla kaynakta gorunuyorsa guven artar)
# =====================================================================
$merged = New-Object System.Collections.Generic.List[object]
$all = @($script:F.ToArray())
foreach ($g in ($all | Group-Object -Property Ad)) {
    $items = @($g.Group)
    $mx = 0
    foreach ($i in $items) { if ($i.Skor -gt $mx) { $mx = $i.Skor } }
    $srcs = @($items | ForEach-Object { $_.Kaynak } | Select-Object -Unique)
    $bonus = [Math]::Min(30, 10 * ($srcs.Count - 1))
    $skor = [Math]::Min(100, $mx + $bonus)
    $var = 'Bilinmiyor'
    $yol = $items[0].Yol
    $ev = @($items | Where-Object { $_.Var -eq 'Evet' })
    $hy = @($items | Where-Object { $_.Var -eq 'Hayir' })
    if ($ev.Count -gt 0) { $var = 'Evet'; $yol = $ev[0].Yol } elseif ($hy.Count -gt 0) { $var = 'Hayir'; $yol = $hy[0].Yol }
    $sonList = @($items | Where-Object { $_.Son } | ForEach-Object { [datetime]$_.Son })
    $ilkList = @($items | Where-Object { $_.Ilk } | ForEach-Object { [datetime]$_.Ilk })
    $silList = @($items | Where-Object { $_.Silinme } | ForEach-Object { [datetime]$_.Silinme })
    $son = $null
    $ilk = $null
    $sil = $null
    if ($sonList.Count -gt 0) { $son = ($sonList | Sort-Object -Descending | Select-Object -First 1) }
    if ($ilkList.Count -gt 0) { $ilk = ($ilkList | Sort-Object | Select-Object -First 1) }
    if ($silList.Count -gt 0) { $sil = ($silList | Sort-Object -Descending | Select-Object -First 1) }
    $notes = @($items | ForEach-Object { $_.Not } | Where-Object { $_ } | Select-Object -Unique)
    if ($var -eq 'Hayir' -and -not $sil) {
        $k = ([string]$g.Name).ToLower()
        if ($script:UsnDel.ContainsKey($k)) { $sil = $script:UsnDel[$k]; $notes += 'silinme zamani USN gunlugunden' }
        if (-not $sil) {
            foreach ($bi in $script:BinItems) {
                $bl = ''
                try { $bl = (Split-Path -Leaf $bi.Orijinal).ToLower() } catch {}
                if ($bl -eq $k -and $bi.Silinme) { $sil = $bi.Silinme; $notes += 'silinme zamani geri donusum kutusu kaydindan'; break }
            }
        }
    }
    $allBenign = (@($items | Where-Object { -not $_.Benign }).Count -eq 0)
    [void]$merged.Add([pscustomobject]@{ Ad = $g.Name; Yol = $yol; Skor = $skor; Var = $var; Son = $son; Ilk = $ilk; Silinme = $sil; Kaynaklar = ($srcs -join ', '); Not = ($notes -join ' ; '); Benign = $allBenign })
}
$ranked = @($merged | Sort-Object -Property @{ Expression = 'Skor'; Descending = $true }, @{ Expression = 'Son'; Descending = $true })
$high = @($ranked | Where-Object { $_.Skor -ge 60 })
$mid = @($ranked | Where-Object { $_.Skor -ge 40 -and $_.Skor -lt 60 })
$low = @($ranked | Where-Object { $_.Skor -lt 40 })
$total = $ranked.Count

# =====================================================================
# SONUC EKRANI
# =====================================================================
Log '' 'Gray'
Log '===================================================================' 'Green'
Log '  SONUC - HileKiran' 'Green'
Log '===================================================================' 'Green'
if ($total -gt 0) {
    $ph = [Math]::Round(100 * $high.Count / $total)
    $pm = [Math]::Round(100 * $mid.Count / $total)
    $pl = 100 - $ph - $pm
    Log ('  Toplam bulgu: ' + $total) 'White'
    Log ('   %' + $ph + ' YUKSEK guven (' + $high.Count + ')  - buyuk ihtimalle gercek, incele') 'Red'
    Log ('   %' + $pm + ' ORTA guven   (' + $mid.Count + ')  - suphe var, tarih/yola bak') 'Yellow'
    Log ('   %' + $pl + ' DUSUK guven  (' + $low.Count + ')  - buyuk ihtimalle yanlis alarm (sadece rapor dosyasinda)') 'DarkGray'
    Log '  (Yuzdeler tahmini dagilimdir, kesin dogruluk orani DEGILDIR.)' 'DarkGray'
} else {
    Log '  Hicbir bulgu yok.' 'Green'
}

Log '' 'Gray'
Log '--- BYPASS TESPITI (iz saklama/temizleme, servis ve ayar durumlari) ---' 'Yellow'
if ($script:Sys.Count -eq 0) { Log '   Uyari yok: Prefetch, servisler, olay gunlukleri, USN gunlugu, Defender ayarlari, zamanlanmis gorevler normal gorunuyor.' 'Green' }
foreach ($s in ($script:Sys | Sort-Object -Property Skor -Descending)) {
    $zt = ''
    if ($s.Zaman) { $zt = '  [olay zamani: ' + (Fmt $s.Zaman) + ']' }
    Log ('   [%' + $s.Skor + '] ' + $s.Baslik + $zt) 'Yellow'
    Log ('        ' + $s.Aciklama) 'DarkGray'
    if ($s.Durum) { Log ('        Durum          : ' + $s.Durum) 'DarkGray' }
    if ($s.Degisim) { Log ('        Son elle degisim: ' + (Fmt $s.Degisim)) 'DarkGray' }
}

Log '' 'Gray'
Log '--- YUKSEK GUVENLI BULGULAR ---' 'Red'
if ($high.Count -eq 0) { Log '   Yok.' 'Green' }
foreach ($m in ($high | Select-Object -First 40)) { Show-Item $m 'Red' }

Log '' 'Gray'
Log '--- ORTA GUVENLI BULGULAR ---' 'Yellow'
if ($mid.Count -eq 0) { Log '   Yok.' 'Green' }
foreach ($m in ($mid | Select-Object -First 25)) {
    $d2 = 'DURUYOR'
    if ($m.Var -eq 'Hayir') { $d2 = 'SILINMIS' }
    if ($m.Var -eq 'Bilinmiyor') { $d2 = '?' }
    Log ('   [%' + $m.Skor + '] ' + $m.Ad + ' | ' + $d2 + ' | son: ' + (Fmt $m.Son) + ' | ' + $m.Yol) 'Yellow'
}
if ($mid.Count -gt 25) { Log ('   ... ve ' + ($mid.Count - 25) + ' tane daha (rapor dosyasinda).') 'DarkGray' }

Log '' 'Gray'
Log '--- CALISTIRILIP SONRA SILINEN PROGRAMLAR (en yeniden eskiye) ---' 'Magenta'
$delProg = @($ranked | Where-Object { $_.Var -eq 'Hayir' -and $_.Kaynaklar -match 'BAM|Prefetch|UserAssist|Amcache|Shimcache|Jump|Recent|Geri' -and -not $_.Benign } | Sort-Object -Property @{ Expression = 'Son'; Descending = $true })
if ($delProg.Count -eq 0) { Log '   Yok.' 'Green' }
foreach ($m in ($delProg | Select-Object -First 25)) {
    $sz = 'silinme zamani bilinmiyor'
    if ($m.Silinme) { $sz = 'silindi: ' + (Fmt $m.Silinme) }
    Log ('   ' + $m.Ad + '  | son calisma: ' + (Fmt $m.Son) + ' | ' + $sz) 'Magenta'
    Log ('        yer: ' + $m.Yol) 'DarkGray'
}
if ($delProg.Count -gt 25) { Log ('   ... ve ' + ($delProg.Count - 25) + ' tane daha (rapor dosyasinda).') 'DarkGray' }

Log '' 'Gray'
Log '--- GERI DONUSUM KUTUSU ---' 'Cyan'
foreach ($bs2 in $script:BinState) { Log ('   ' + $bs2) 'Gray' }
foreach ($kv in $script:BinEmptied.GetEnumerator()) { Log ('   ' + $kv.Key + ' en son bosaltma/kalici silme (USN kaydi): ' + (Fmt $kv.Value)) 'Cyan' }
if ($script:BinEmptied.Count -eq 0) { Log '   USN gunlugunde kutu bosaltma kaydi bulunamadi (kayit eski/yok olabilir).' 'DarkGray' }
$binX = @($script:BinItems | Where-Object { $_.Orijinal -match '(?i)\.(exe|jar|rar|zip|7z|bat|ps1|scr)$' } | Sort-Object -Property @{ Expression = 'Silinme'; Descending = $true } | Select-Object -First 10)
foreach ($bi in $binX) { Log ('   kutuda: ' + $bi.Orijinal + '  (silindi: ' + (Fmt $bi.Silinme) + ')') 'Gray' }

Log '' 'Gray'
Log '--- SON 30 GUNDE SILINEN exe/jar/zip/rar/7z (USN gunlugu, en yeni 15) ---' 'Cyan'
$ur = @($script:UsnRecent | Where-Object { $_.Ad -notmatch '^(~\$|\$)' } | Sort-Object -Property @{ Expression = 'Zaman'; Descending = $true } | Select-Object -First 15)
if ($ur.Count -eq 0) { Log '   Kayit yok.' 'DarkGray' }
foreach ($u in $ur) { Log ('   ' + (Fmt $u.Zaman) + '  ' + $u.Ad + '  (' + $u.Surucu + ')') 'Gray' }

Log '' 'Gray'
Log '--- USB DEPOLAMA GECMISI ---' 'Cyan'
if ($script:UsbList.Count -eq 0) { Log '   Kayit yok.' 'DarkGray' }
foreach ($u in $script:UsbList) { Log ('   ' + $u.Ad + '  | ilk baglanti: ' + (Fmt $u.Ilk) + ' | son kayit: ' + (Fmt $u.Son)) 'Gray' }

Log '' 'Gray'
Log '--- CALISAN JAVA (Minecraft) ---' 'Cyan'
if ($script:JavaInfo.Count -eq 0) { Log '   Su an calisan Java yok. Hile acikken/Minecraft acikken tekrar calistirirsan enjeksiyon kontrolu de yapilir.' 'DarkGray' }
foreach ($j in $script:JavaInfo) { Log ('   ' + $j) 'Gray' }

Log '' 'Gray'
Log '--- BU ARACIN GOREMEDIGI SEYLER (durust sinirlar) ---' 'DarkGray'
Log '   * Bellekte (RAM) calisan hilelerin tamami: sadece secili process stringleri taranir; korumali (PPL) process ler (csrss, MsMpEng, SgrmBroker) okunamaz. DMA/ikinci PC gibi donanim hileleri gorulmez' 'DarkGray'
Log '   * Adi ve icerigi listede olmayan, obfuscate edilmis ozel (private) hileler' 'DarkGray'
Log '   * Kesin silinme zamani: sadece USN gunlugunde kaydi varsa bulunur (gunluk eskirse kaybolur)' 'DarkGray'
Log '   * Bu bir kanit degil, incelenecek ipuclari listesidir; dosyayi acip elle dogrula.' 'DarkGray'

# tam liste sadece rapor dosyasina
Log '' 'Gray' $true
Log '=================== TAM LISTE (tum bulgular, sadece rapor dosyasi) ===================' 'Gray' $true
foreach ($m in $ranked) { Show-Item $m 'Gray' $true }
Log '' 'Gray' $true
Log '=================== SON 30 GUN SILINENLER (USN, tumu) ===================' 'Gray' $true
foreach ($u in ($script:UsnRecent | Sort-Object -Property @{ Expression = 'Zaman'; Descending = $true } | Select-Object -First 300)) { Log ('   ' + (Fmt $u.Zaman) + '  ' + $u.Ad + '  (' + $u.Surucu + ')') 'Gray' $true }

$el = [int]((Get-Date) - $Started).TotalSeconds
Log '' 'Gray'
Log ('Tarama suresi: ' + $el + ' sn. Rapor kaydedildi: ' + $ReportPath) 'Cyan'
try {
    [IO.File]::WriteAllLines($ReportPath, $script:Rep.ToArray(), (New-Object System.Text.UTF8Encoding $true))
} catch { Write-Host 'Rapor dosyasi yazilamadi.' -ForegroundColor Red }
