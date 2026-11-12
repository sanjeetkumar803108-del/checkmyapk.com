export interface ElfBinaryAudit {
  fileName: string;
  baseName: string;
  abi: string;
  sizeBytes: number;
  archBits: 32 | 64;
  isThirdPartyRuntime: boolean;
  pie: boolean;
  nx: boolean;
  stackCanary: boolean;
  relro: 'FULL' | 'PARTIAL' | 'NONE';
}

export interface NativeElfSummary {
  totalSoFiles: number;
  uniqueLibrariesCount: number;
  appLibrariesCount: number;
  hardeningWeakCount: number;
  nativeStringsScannedKb: number;
  libraries: ElfBinaryAudit[];
}

export interface NativeFinding {
  category: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'PASS';
  proof: string;
  description: string;
  remediation: string;
  owaspRef: string;
}

const KNOWN_RUNTIME_LIB_PREFIXES = [
  'libflutter', 'libhermes', 'libjsi', 'libjsc', 'libreactnative', 'libreact_',
  'libfbjni', 'libfolly', 'libglog', 'libyoga', 'libc++_shared', 'libunity',
  'libil2cpp', 'libmain', 'libv8', 'libsqlite', 'libsqlcipher', 'libconscrypt',
  'libcronet', 'libimage_processing', 'libandroidx', 'libdatastore', 'librealm',
  'libpdfium', 'libwebp', 'libgifimage', 'libnative-imagetranscoder', 'libnative-filters',
  'libturbomodule', 'libfabricjni', 'libuimanagerjni', 'librrc_', 'libmapbufferjni',
  'libmmkv', 'libappmodules', 'libexpo', 'libworklets', 'libreanimated', 'libgesturehandler'
];

const ABI_PRIORITY: Record<string, number> = {
  'arm64-v8a': 4,
  'armeabi-v7a': 3,
  'x86_64': 2,
  'x86': 1
};

export function isThirdPartyRuntimeLib(baseName: string): boolean {
  const lower = baseName.toLowerCase();
  if (lower === 'libapp.so') return false; // Flutter AOT app bundle stays high priority for string scan, marked separately for ELF checks
  return KNOWN_RUNTIME_LIB_PREFIXES.some(prefix => lower.startsWith(prefix));
}

function readU64AsNumber(buf: Buffer, off: number): number {
  const low = buf.readUInt32LE(off);
  const high = buf.readUInt32LE(off + 4);
  return high * 0x100000000 + low;
}

/**
 * Extracts printable ASCII strings >= minLen from binary archives (ELF .so, Flutter libapp.so, Hermes .bundle).
 */
export function extractPrintableAscii(buf: Buffer, minLen = 8, maxOutBytes = 4 * 1024 * 1024): string {
  const chunks: string[] = [];
  let totalLen = 0;
  let runStart = -1;

  const limit = Math.min(buf.length, 32 * 1024 * 1024); // Cap single binary scan at 32MB for predictable RAM/CPU
  for (let i = 0; i < limit; i++) {
    const b = buf[i];
    const printable = b >= 0x20 && b <= 0x7e;
    if (printable) {
      if (runStart === -1) runStart = i;
    } else if (runStart !== -1) {
      const len = i - runStart;
      if (len >= minLen && len <= 1024) {
        chunks.push(buf.toString('latin1', runStart, i));
        totalLen += len + 1;
        if (totalLen >= maxOutBytes) break;
      }
      runStart = -1;
    }
  }
  if (runStart !== -1 && totalLen < maxOutBytes) {
    const len = limit - runStart;
    if (len >= minLen && len <= 1024) {
      chunks.push(buf.toString('latin1', runStart, limit));
    }
  }
  return chunks.join('\n');
}

function parseElfBinary(fileName: string, baseName: string, abi: string, buf: Buffer): ElfBinaryAudit | null {
  if (buf.length < 64) return null;
  // Verify ELF magic: 0x7F 'E' 'L' 'F'
  if (buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46) {
    return null;
  }
  const eiClass = buf[4]; // 1 = 32-bit, 2 = 64-bit
  const eiData = buf[5];  // 1 = Little Endian
  if (eiData !== 1 || (eiClass !== 1 && eiClass !== 2)) {
    return null;
  }

  const archBits: 32 | 64 = eiClass === 2 ? 64 : 32;
  const eType = buf.readUInt16LE(16);
  const pie = eType === 3; // ET_DYN

  const phOff = archBits === 64 ? readU64AsNumber(buf, 0x20) : buf.readUInt32LE(0x1c);
  const phEntSize = archBits === 64 ? buf.readUInt16LE(0x36) : buf.readUInt16LE(0x2a);
  const phNum = archBits === 64 ? buf.readUInt16LE(0x38) : buf.readUInt16LE(0x2c);

  let nx = true; // Modern Android defaults non-executable unless PT_GNU_STACK sets PF_X
  let hasRelro = false;
  let hasBindNow = false;

  if (phOff > 0 && phEntSize >= (archBits === 64 ? 56 : 32) && phNum > 0 && phNum < 256) {
    for (let i = 0; i < phNum; i++) {
      const off = phOff + i * phEntSize;
      if (off + phEntSize > buf.length) break;

      const pType = buf.readUInt32LE(off);
      const pFlags = archBits === 64 ? buf.readUInt32LE(off + 4) : buf.readUInt32LE(off + 24);
      const pOffset = archBits === 64 ? readU64AsNumber(buf, off + 8) : buf.readUInt32LE(off + 4);
      const pFilesz = archBits === 64 ? readU64AsNumber(buf, off + 32) : buf.readUInt32LE(off + 16);

      if (pType === 0x6474e551) { // PT_GNU_STACK
        if ((pFlags & 0x1) !== 0) { // PF_X set
          nx = false;
        }
      } else if (pType === 0x6474e552) { // PT_GNU_RELRO
        hasRelro = true;
      } else if (pType === 2 && pOffset > 0 && pOffset + pFilesz <= buf.length) { // PT_DYNAMIC
        const dynEntrySize = archBits === 64 ? 16 : 8;
        const maxDyn = Math.min(Math.floor(pFilesz / dynEntrySize), 2048);
        for (let d = 0; d < maxDyn; d++) {
          const dOff = pOffset + d * dynEntrySize;
          const dTag = archBits === 64 ? buf.readInt32LE(dOff) : buf.readInt32LE(dOff);
          const dTagHigh = archBits === 64 ? buf.readInt32LE(dOff + 4) : 0;
          if (dTag === 0 && dTagHigh === 0) break; // DT_NULL

          const dVal = archBits === 64 ? buf.readUInt32LE(dOff + 8) : buf.readUInt32LE(dOff + 4);
          if (dTag === 24 && dTagHigh === 0) { // DT_BIND_NOW
            hasBindNow = true;
          } else if (dTag === 30 && dTagHigh === 0 && (dVal & 0x8) !== 0) { // DT_FLAGS -> DF_BIND_NOW
            hasBindNow = true;
          } else if ((dTag >>> 0) === 0x6ffffffb && (dVal & 0x1) !== 0) { // DT_FLAGS_1 -> DF_1_NOW
            hasBindNow = true;
          }
        }
      }
    }
  }

  const relro: ElfBinaryAudit['relro'] = !hasRelro ? 'NONE' : hasBindNow ? 'FULL' : 'PARTIAL';
  const stackCanary = buf.includes('__stack_chk_fail') || buf.includes('__stack_chk_guard');

  return {
    fileName,
    baseName,
    abi,
    sizeBytes: buf.length,
    archBits,
    isThirdPartyRuntime: isThirdPartyRuntimeLib(baseName),
    pie,
    nx,
    stackCanary,
    relro
  };
}

/**
 * Inspects native Android ELF (.so) shared libraries for binary hardening flags (PIE, NX, Stack Canary, RELRO)
 * and extracts bounded ASCII strings from custom JNI libraries and Flutter AOT snapshots for secret/API scanning.
 */
export function scanNativeElfLibraries(
  soEntries: Array<{ entryName: string; getData: () => Buffer }>
): {
  summary: NativeElfSummary;
  findings: NativeFinding[];
  extractedStringChunks: Array<{ sourceName: string; text: string }>;
} {
  const uniqueByBase = new Map<string, { entry: { entryName: string; getData: () => Buffer }; abi: string; prio: number }>();

  for (const entry of soEntries) {
    const parts = entry.entryName.split('/');
    const baseName = parts[parts.length - 1] || entry.entryName;
    const abi = parts.length >= 3 && parts[0] === 'lib' ? parts[1] : 'unknown';
    const prio = ABI_PRIORITY[abi] || 0;
    const existing = uniqueByBase.get(baseName);
    if (!existing || prio > existing.prio) {
      uniqueByBase.set(baseName, { entry, abi, prio });
    }
  }

  const libraries: ElfBinaryAudit[] = [];
  const findings: NativeFinding[] = [];
  const extractedStringChunks: Array<{ sourceName: string; text: string }> = [];
  let nativeStringsBytes = 0;

  // Sort so app-owned native libraries come first before heavy runtime frameworks
  const ordered = Array.from(uniqueByBase.entries()).sort((a, b) => {
    const aRt = isThirdPartyRuntimeLib(a[0]) ? 1 : 0;
    const bRt = isThirdPartyRuntimeLib(b[0]) ? 1 : 0;
    return aRt - bRt;
  });

  for (const [baseName, item] of ordered) {
    let buf: Buffer;
    try {
      buf = item.entry.getData();
    } catch {
      continue;
    }

    const parsed = parseElfBinary(item.entry.entryName, baseName, item.abi, buf);
    if (!parsed) continue;
    libraries.push(parsed);

    const isFlutterAppSnapshot = baseName.toLowerCase() === 'libapp.so';
    // Extract strings from app-custom JNI libraries or Flutter Dart AOT snapshot (libapp.so)
    if ((!parsed.isThirdPartyRuntime || isFlutterAppSnapshot) && buf.length <= 32 * 1024 * 1024 && nativeStringsBytes < 12 * 1024 * 1024) {
      const asciiText = extractPrintableAscii(buf, 8, 3 * 1024 * 1024);
      if (asciiText.length > 0) {
        nativeStringsBytes += asciiText.length;
        extractedStringChunks.push({ sourceName: item.entry.entryName, text: asciiText });
      }
    }

    // Evaluate hardening strictly on app-owned custom JNI libraries (exclude libapp.so AOT data container & 3rd-party SDK runtimes)
    if (!parsed.isThirdPartyRuntime && !isFlutterAppSnapshot) {
      const missing: string[] = [];
      if (!parsed.nx) missing.push('Executable Stack (NX disabled)');
      if (!parsed.pie) missing.push('Missing PIE (ASLR bypass risk)');
      if (parsed.relro === 'NONE') missing.push('No RELRO (GOT overwrite risk)');
      if (!parsed.stackCanary) missing.push('No Stack Canary (__stack_chk_fail)');

      if (missing.length > 0) {
        const hasSevere = !parsed.nx || !parsed.pie;
        findings.push({
          category: 'Native Binary (.so ELF)',
          type: `Native Library Missing Binary Protections (${baseName})`,
          severity: hasSevere ? 'HIGH' : 'MEDIUM',
          proof: `${item.entry.entryName} (${parsed.archBits}-bit ${parsed.abi}): ${missing.join(', ')}; RELRO=${parsed.relro}`,
          description: `Native C/C++ shared library ${baseName} lacks modern compiler memory mitigations (${missing.join(', ')}), increasing exploitability of memory corruption or GOT/stack overflow bugs.`,
          remediation: 'Compile all NDK C/C++ modules with -fstack-protector-strong -fPIE -Wl,-z,noexecstack -Wl,-z,relro,-z,now in CMakeLists.txt / Application.mk.',
          owaspRef: 'MASVS-CODE-2'
        });
      }
    }
  }

  const appLibs = libraries.filter(l => !l.isThirdPartyRuntime && l.baseName.toLowerCase() !== 'libapp.so');
  const hardeningWeakCount = findings.length;

  if (libraries.length > 0 && hardeningWeakCount === 0 && appLibs.length > 0) {
    findings.push({
      category: 'Native Binary (.so ELF)',
      type: `Native ELF Binary Mitigations Verified (${appLibs.length} App Libs)`,
      severity: 'PASS',
      proof: `Audited ${libraries.length} unique ELF shared binaries (${appLibs.length} custom JNI libs): PIE, NX non-executable stack, RELRO, and Stack Canary protections verified.`,
      description: 'App-compiled native C/C++ libraries enforce PIE ASLR, non-executable stack, RELRO GOT protection, and stack buffer canaries.',
      remediation: 'Keep NDK default hardening flags enabled across all release ABI targets.',
      owaspRef: 'MASVS-CODE-2'
    });
  }

  return {
    summary: {
      totalSoFiles: soEntries.length,
      uniqueLibrariesCount: libraries.length,
      appLibrariesCount: appLibs.length,
      hardeningWeakCount,
      nativeStringsScannedKb: Math.round(nativeStringsBytes / 1024),
      libraries: libraries.slice(0, 16)
    },
    findings,
    extractedStringChunks
  };
}
