export interface TaintFlowFinding {
  source: string;
  sink: string;
  methodSignature: string;
  detail: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  owaspRef: string;
  hopCount?: number;
  callChain?: string[];
}

export interface DexBytecodeFinding {
  category: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  proof: string;
  description: string;
  remediation: string;
  owaspRef: string;
}

export interface CallGraphHotspot {
  callerMethod: string;
  calleeSignature: string;
  category: 'WebView' | 'Crypto' | 'Network/SSL' | 'Command/Code' | 'IPC/Storage';
}

export interface DexBytecodeGraphSummary {
  dexCount: number;
  totalClasses: number;
  appClasses: number;
  methodsAnalyzed: number;
  instructionsScanned: number;
  durationMs: number;
  interproceduralPathsCount?: number;
  pinningSignals?: string[];
  taintPaths: TaintFlowFinding[];
  callGraphHotspots: CallGraphHotspot[];
}

export interface DexAnalysisOutput {
  summary: DexBytecodeGraphSummary;
  findings: DexBytecodeFinding[];
}

interface RegisterState {
  taintSource: string | null;
  paramOrigins: number[];
  callOriginIdx: number | null;
  strConst: string | null;
  numConst: number | null;
  typeConst: string | null;
}

interface SinkHitTemplate {
  sinkName: string;
  findingType: string;
  severity: 'CRITICAL' | 'HIGH';
  owaspRef: string;
  description: string;
  remediation: string;
}

interface ArgTaintOrigin {
  taintSource: string | null;
  paramOrigins: number[];
  callOriginIdx: number | null;
}

interface MethodCallRecord {
  calleeKey: string;
  calleeReadableSig: string;
  argInfos: ArgTaintOrigin[];
}

interface MethodSummary {
  key: string;
  readableSig: string;
  directParamSinks: Map<number, SinkHitTemplate[]>;
  localCallSinks: Array<{ callOriginIdx: number; sink: SinkHitTemplate }>;
  returnsTaintSource: string | null;
  returnParamIndices: Set<number>;
  returnCallOrigins: number[];
  calls: MethodCallRecord[];
}

// Official Dalvik bytecode 16-bit code-unit widths indexed by low opcode byte (0x00..0xff)
const DALVIK_OPCODE_WIDTHS = new Uint8Array([
  // 0x00 - 0x0f
  1, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 1, 1, 1, 1, 1,
  // 0x10 - 0x1f
  1, 1, 1, 2, 3, 2, 2, 3, 5, 2, 2, 3, 2, 1, 1, 2,
  // 0x20 - 0x2f
  2, 1, 2, 2, 3, 3, 3, 1, 1, 2, 3, 3, 3, 2, 2, 2,
  // 0x30 - 0x3f
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1,
  // 0x40 - 0x4f
  1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  // 0x50 - 0x5f
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  // 0x60 - 0x6f
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3,
  // 0x70 - 0x7f
  3, 3, 3, 1, 3, 3, 3, 3, 3, 1, 1, 1, 1, 1, 1, 1,
  // 0x80 - 0x8f
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  // 0x90 - 0x9f
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  // 0xa0 - 0xaf
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  // 0xb0 - 0xbf
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  // 0xc0 - 0xcf
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  // 0xd0 - 0xdf
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  // 0xe0 - 0xef
  2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  // 0xf0 - 0xff
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 4, 4, 3, 3, 2, 2,
]);

const NOISE_CLASS_PREFIXES = [
  'Ljava/', 'Ljavax/', 'Lsun/', 'Landroid/', 'Landroidx/', 'Lkotlin/', 'Lkotlinx/',
  'Ldalvik/', 'Lorg/apache/', 'Lorg/json/', 'Lorg/w3c/', 'Lorg/xml/', 'Lorg/intellij/',
  'Lorg/jetbrains/', 'Lcom/google/android/', 'Lcom/google/firebase/', 'Lcom/google/gson/',
  'Lcom/google/protobuf/', 'Lcom/google/common/', 'Lokhttp3/', 'Lokio/', 'Lretrofit2/',
  'Lcom/squareup/', 'Lcom/bumptech/', 'Lio/reactivex/', 'Lorg/chromium/'
];

function isNoiseFrameworkClass(desc: string, appPkgPrefix: string): boolean {
  if (appPkgPrefix && desc.startsWith(appPkgPrefix)) return false;
  return NOISE_CLASS_PREFIXES.some(prefix => desc.startsWith(prefix));
}

function readUleb128(buf: Buffer, posObj: { pos: number }): number {
  let result = 0;
  let shift = 0;
  while (posObj.pos < buf.length && shift < 35) {
    const byte = buf[posObj.pos++];
    result |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
  }
  return result >>> 0;
}

function formatReadableClass(desc: string): string {
  if (desc.startsWith('L') && desc.endsWith(';')) {
    return desc.slice(1, -1).replace(/\//g, '.');
  }
  return desc;
}

function decodeMutf8String(buf: Buffer, strDataOff: number): string {
  if (strDataOff <= 0 || strDataOff >= buf.length) return '';
  const cursor = { pos: strDataOff };
  readUleb128(buf, cursor); // UTF-16 char count prefix
  const start = cursor.pos;
  let end = start;
  while (end < buf.length && buf[end] !== 0) {
    end++;
    if (end - start > 512) break; // Cap pathological symbol lengths
  }
  return buf.toString('utf8', start, end);
}

class DexFileReader {
  private readonly stringCache = new Map<number, string>();
  private readonly stringIdsSize: number;
  private readonly stringIdsOff: number;
  private readonly typeIdsSize: number;
  private readonly typeIdsOff: number;
  private readonly protoIdsSize: number;
  private readonly protoIdsOff: number;
  private readonly methodIdsSize: number;
  private readonly methodIdsOff: number;
  readonly classDefsSize: number;
  readonly classDefsOff: number;

  constructor(readonly buf: Buffer) {
    this.stringIdsSize = buf.readUInt32LE(0x38);
    this.stringIdsOff = buf.readUInt32LE(0x3c);
    this.typeIdsSize = buf.readUInt32LE(0x40);
    this.typeIdsOff = buf.readUInt32LE(0x44);
    this.protoIdsSize = buf.readUInt32LE(0x48);
    this.protoIdsOff = buf.readUInt32LE(0x4c);
    this.methodIdsSize = buf.readUInt32LE(0x58);
    this.methodIdsOff = buf.readUInt32LE(0x5c);
    this.classDefsSize = buf.readUInt32LE(0x60);
    this.classDefsOff = buf.readUInt32LE(0x64);
  }

  getString(idx: number): string {
    if (idx < 0 || idx >= this.stringIdsSize) return '';
    const cached = this.stringCache.get(idx);
    if (cached !== undefined) return cached;
    const entryOff = this.stringIdsOff + idx * 4;
    if (entryOff + 4 > this.buf.length) return '';
    const dataOff = this.buf.readUInt32LE(entryOff);
    const val = decodeMutf8String(this.buf, dataOff);
    if (this.stringCache.size < 80000) {
      this.stringCache.set(idx, val);
    }
    return val;
  }

  getTypeDescriptor(typeIdx: number): string {
    if (typeIdx < 0 || typeIdx >= this.typeIdsSize) return '';
    const off = this.typeIdsOff + typeIdx * 4;
    if (off + 4 > this.buf.length) return '';
    return this.getString(this.buf.readUInt32LE(off));
  }

  getProtoShorty(protoIdx: number): string {
    if (protoIdx < 0 || protoIdx >= this.protoIdsSize) return '';
    const off = this.protoIdsOff + protoIdx * 12;
    if (off + 12 > this.buf.length) return '';
    return this.getString(this.buf.readUInt32LE(off));
  }

  getMethodRef(methodIdx: number): { classDesc: string; name: string; canonicalKey: string } {
    if (methodIdx < 0 || methodIdx >= this.methodIdsSize) {
      return { classDesc: '', name: '', canonicalKey: '' };
    }
    const off = this.methodIdsOff + methodIdx * 8;
    if (off + 8 > this.buf.length) return { classDesc: '', name: '', canonicalKey: '' };
    const classIdx = this.buf.readUInt16LE(off);
    const protoIdx = this.buf.readUInt16LE(off + 2);
    const nameIdx = this.buf.readUInt32LE(off + 4);
    const classDesc = this.getTypeDescriptor(classIdx);
    const name = this.getString(nameIdx);
    const shorty = this.getProtoShorty(protoIdx);
    return {
      classDesc,
      name,
      canonicalKey: `${classDesc}->${name}:${shorty}`
    };
  }

  getClassInterfaces(interfacesOff: number): string[] {
    if (interfacesOff <= 0 || interfacesOff + 4 > this.buf.length) return [];
    const size = this.buf.readUInt32LE(interfacesOff);
    if (size > 64 || interfacesOff + 4 + size * 2 > this.buf.length) return [];
    const list: string[] = [];
    for (let i = 0; i < size; i++) {
      const typeIdx = this.buf.readUInt16LE(interfacesOff + 4 + i * 2);
      list.push(this.getTypeDescriptor(typeIdx));
    }
    return list;
  }
}

function isValidDexHeader(buf: Buffer): boolean {
  if (buf.length < 0x70) return false;
  // ASCII "dex\n03"
  return buf[0] === 0x64 && buf[1] === 0x65 && buf[2] === 0x78 && buf[3] === 0x0a;
}

function classifyTaintSource(classDesc: string, methodName: string): string | null {
  if (classDesc === 'Landroid/content/Intent;') {
    if (
      methodName === 'getStringExtra' ||
      methodName === 'getCharSequenceExtra' ||
      methodName === 'getData' ||
      methodName === 'getDataString' ||
      methodName === 'getExtras' ||
      methodName === 'getParcelableExtra'
    ) {
      return `Intent.${methodName}()`;
    }
  }
  if (methodName === 'getIntent' && (classDesc === 'Landroid/app/Activity;' || classDesc.endsWith('Activity;'))) {
    return 'Activity.getIntent()';
  }
  if (classDesc === 'Landroid/net/Uri;' && (methodName === 'getQueryParameter' || methodName === 'getPath' || methodName === 'getEncodedQuery')) {
    return `Uri.${methodName}()`;
  }
  if (classDesc === 'Landroid/os/Bundle;' && (methodName === 'getString' || methodName === 'getCharSequence')) {
    return `Bundle.${methodName}()`;
  }
  if (classDesc === 'Landroid/content/ClipboardManager;' && methodName === 'getPrimaryClip') {
    return 'ClipboardManager.getPrimaryClip()';
  }
  return null;
}

function classifyCallCategory(classDesc: string, methodName: string): CallGraphHotspot['category'] | null {
  if (classDesc.startsWith('Landroid/webkit/')) return 'WebView';
  if (classDesc.startsWith('Ljavax/crypto/') || methodName === 'getInstance' && classDesc === 'Ljava/security/MessageDigest;') return 'Crypto';
  if (classDesc === 'Ljavax/net/ssl/HttpsURLConnection;' || classDesc === 'Ljavax/net/ssl/SSLContext;') return 'Network/SSL';
  if (classDesc === 'Ljava/lang/Runtime;' && methodName === 'exec') return 'Command/Code';
  if (classDesc === 'Ldalvik/system/DexClassLoader;' || classDesc === 'Ldalvik/system/PathClassLoader;') return 'Command/Code';
  if (classDesc === 'Landroid/database/sqlite/SQLiteDatabase;' && (methodName === 'rawQuery' || methodName === 'execSQL')) return 'IPC/Storage';
  if (classDesc === 'Landroid/app/PendingIntent;') return 'IPC/Storage';
  return null;
}

function mergeParamOrigins(a: number[], b: number[]): number[] {
  if (a.length === 0) return b.slice(0, 4);
  if (b.length === 0) return a.slice(0, 4);
  const out = [...a];
  for (const x of b) {
    if (!out.includes(x) && out.length < 4) out.push(x);
  }
  return out;
}

function recordUnresolvedParamOrCallSink(
  summary: MethodSummary,
  candidateRegs: number[],
  getReg: (r: number) => RegisterState,
  sink: SinkHitTemplate
) {
  for (const regIdx of candidateRegs) {
    const st = getReg(regIdx);
    for (const pIdx of st.paramOrigins) {
      const existing = summary.directParamSinks.get(pIdx) || [];
      if (!existing.some(e => e.sinkName === sink.sinkName)) {
        existing.push(sink);
        summary.directParamSinks.set(pIdx, existing);
      }
    }
    if (st.callOriginIdx !== null && summary.localCallSinks.length < 32) {
      summary.localCallSinks.push({ callOriginIdx: st.callOriginIdx, sink });
    }
  }
}

/**
 * Inspects compiled Dalvik .dex buffers at binary class/method/opcode granularity
 * to build intraprocedural & cross-method source-to-sink taint paths, detect SSL pinning,
 * and verify crypto/SSL/WebView sinks.
 */
export function analyzeDexBytecode(
  dexFiles: Array<{ name: string; buffer: Buffer }>,
  appPackageName = ''
): DexAnalysisOutput {
  const startTime = Date.now();
  const appPkgPrefix = appPackageName ? `L${appPackageName.replace(/\./g, '/')}/` : '';

  let totalClasses = 0;
  let appClasses = 0;
  let methodsAnalyzed = 0;
  let instructionsScanned = 0;

  const findings: DexBytecodeFinding[] = [];
  const taintPaths: TaintFlowFinding[] = [];
  const hotspotMap = new Map<string, CallGraphHotspot>();
  const dedupFindingKeys = new Set<string>();
  const methodSummaries = new Map<string, MethodSummary>();
  const pinningSignals = new Set<string>();

  const addFinding = (f: DexBytecodeFinding) => {
    const key = `${f.type}::${f.proof.slice(0, 120)}`;
    if (!dedupFindingKeys.has(key)) {
      dedupFindingKeys.add(key);
      findings.push(f);
    }
  };

  const addHotspot = (h: CallGraphHotspot) => {
    const key = `${h.callerMethod}->${h.calleeSignature}`;
    if (!hotspotMap.has(key) && hotspotMap.size < 25) {
      hotspotMap.set(key, h);
    }
  };

  for (const dex of dexFiles) {
    if (!isValidDexHeader(dex.buffer)) continue;
    const reader = new DexFileReader(dex.buffer);
    totalClasses += reader.classDefsSize;

    for (let cIdx = 0; cIdx < reader.classDefsSize; cIdx++) {
      const defOff = reader.classDefsOff + cIdx * 32;
      if (defOff + 32 > dex.buffer.length) break;

      const classTypeIdx = dex.buffer.readUInt32LE(defOff);
      const superclassIdx = dex.buffer.readUInt32LE(defOff + 8);
      const interfacesOff = dex.buffer.readUInt32LE(defOff + 12);
      const classDataOff = dex.buffer.readUInt32LE(defOff + 24);
      if (classDataOff === 0 || classDataOff >= dex.buffer.length) continue;

      const classDesc = reader.getTypeDescriptor(classTypeIdx);
      if (!classDesc || isNoiseFrameworkClass(classDesc, appPkgPrefix)) continue;

      appClasses++;
      const readableClass = formatReadableClass(classDesc);
      const interfaces = reader.getClassInterfaces(interfacesOff);
      const superclassDesc = superclassIdx !== 0xffffffff ? reader.getTypeDescriptor(superclassIdx) : '';

      const isTrustManager =
        interfaces.includes('Ljavax/net/ssl/X509TrustManager;') ||
        interfaces.includes('Ljavax/net/ssl/X509ExtendedTrustManager;');
      const isHostnameVerifier = interfaces.includes('Ljavax/net/ssl/HostnameVerifier;');
      const isWebViewClient = superclassDesc.includes('WebViewClient');

      // Parse class_data_item (ULEB128 counts + method definitions)
      const cursor = { pos: classDataOff };
      const staticFieldsSize = readUleb128(dex.buffer, cursor);
      const instanceFieldsSize = readUleb128(dex.buffer, cursor);
      const directMethodsSize = readUleb128(dex.buffer, cursor);
      const virtualMethodsSize = readUleb128(dex.buffer, cursor);

      if (staticFieldsSize > 5000 || instanceFieldsSize > 5000 || directMethodsSize > 5000 || virtualMethodsSize > 5000) {
        continue;
      }

      // Skip encoded_field entries (each is 2 ULEB128s)
      for (let i = 0; i < staticFieldsSize + instanceFieldsSize; i++) {
        readUleb128(dex.buffer, cursor);
        readUleb128(dex.buffer, cursor);
      }

      let classEnabledJs = false;
      let classAddedJsBridge = false;
      let jsBridgeMethod = '';

      const totalClassMethods = directMethodsSize + virtualMethodsSize;
      for (let mSection = 0; mSection < 2; mSection++) {
        const count = mSection === 0 ? directMethodsSize : virtualMethodsSize;
        let runningMethodIdx = 0;

        for (let mIdx = 0; mIdx < count && cursor.pos < dex.buffer.length; mIdx++) {
          runningMethodIdx += readUleb128(dex.buffer, cursor);
          const accessFlags = readUleb128(dex.buffer, cursor);
          const codeOff = readUleb128(dex.buffer, cursor);

          if (codeOff === 0 || codeOff + 16 > dex.buffer.length) continue;

          const methodInfo = reader.getMethodRef(runningMethodIdx);
          const methodName = methodInfo.name || 'unknown';
          const fullMethodSig = `${readableClass}.${methodName}()`;
          const canonicalMethodKey = methodInfo.canonicalKey || `${classDesc}->${methodName}:`;

          const registersSize = dex.buffer.readUInt16LE(codeOff);
          const insSize = dex.buffer.readUInt16LE(codeOff + 2);
          const isStaticMethod = (accessFlags & 0x0008) !== 0;
          const firstParamReg = Math.max(0, registersSize - insSize);

          const insnsSize = dex.buffer.readUInt32LE(codeOff + 12);
          const insnsStart = codeOff + 16;
          if (insnsSize === 0 || insnsSize > 4000 || insnsStart + insnsSize * 2 > dex.buffer.length) continue;

          methodsAnalyzed++;

          const methodSummary: MethodSummary = {
            key: canonicalMethodKey,
            readableSig: fullMethodSig,
            directParamSinks: new Map(),
            localCallSinks: [],
            returnsTaintSource: null,
            returnParamIndices: new Set(),
            returnCallOrigins: [],
            calls: []
          };

          // TrustManager & HostnameVerifier bytecode-level inspection counters
          let hasThrow = false;
          let hasMeaningfulCall = false;
          let opcodeCount = 0;
          let returnedOneConstant = false;

          // Intraprocedural register tracking (seeded with incoming p0..pN parameter origins)
          const regs = new Map<number, RegisterState>();
          const getReg = (r: number): RegisterState => {
            let st = regs.get(r);
            if (!st) {
              const pIdx = r - firstParamReg;
              const paramOrigins =
                r >= firstParamReg && r < registersSize && (isStaticMethod || pIdx > 0)
                  ? [pIdx]
                  : [];
              st = { taintSource: null, paramOrigins, callOriginIdx: null, strConst: null, numConst: null, typeConst: null };
              regs.set(r, st);
            }
            return st;
          };
          let lastInvokeResult: RegisterState | null = null;

          let pc = 0;
          while (pc < insnsSize) {
            const word0 = dex.buffer.readUInt16LE(insnsStart + pc * 2);
            instructionsScanned++;
            opcodeCount++;

            // Handle variable-length switch / array data payloads first
            if (word0 === 0x0100 && pc + 2 <= insnsSize) {
              const size = dex.buffer.readUInt16LE(insnsStart + (pc + 1) * 2);
              pc += size * 2 + 4;
              continue;
            }
            if (word0 === 0x0200 && pc + 2 <= insnsSize) {
              const size = dex.buffer.readUInt16LE(insnsStart + (pc + 1) * 2);
              pc += size * 4 + 2;
              continue;
            }
            if (word0 === 0x0300 && pc + 4 <= insnsSize) {
              const elemWidth = dex.buffer.readUInt16LE(insnsStart + (pc + 1) * 2);
              const size = dex.buffer.readUInt32LE(insnsStart + (pc + 2) * 2);
              pc += Math.floor((size * elemWidth + 1) / 2) + 4;
              continue;
            }

            const op = word0 & 0xff;
            const width = DALVIK_OPCODE_WIDTHS[op] || 1;
            if (pc + width > insnsSize) break;

            // Register moves: move vA, vB / move-object vA, vB
            if (op === 0x01 || op === 0x07) {
              const vA = (word0 >> 8) & 0x0f;
              const vB = (word0 >> 12) & 0x0f;
              regs.set(vA, { ...getReg(vB) });
              lastInvokeResult = null;
            } else if ((op === 0x02 || op === 0x08) && width >= 2) {
              const vAA = (word0 >> 8) & 0xff;
              const vBBBB = dex.buffer.readUInt16LE(insnsStart + (pc + 1) * 2);
              regs.set(vAA, { ...getReg(vBBBB) });
              lastInvokeResult = null;
            } else if (op === 0x0a || op === 0x0b || op === 0x0c) {
              // move-result / move-result-object
              const vAA = (word0 >> 8) & 0xff;
              regs.set(
                vAA,
                lastInvokeResult
                  ? { ...lastInvokeResult, paramOrigins: [...lastInvokeResult.paramOrigins] }
                  : { taintSource: null, paramOrigins: [], callOriginIdx: null, strConst: null, numConst: null, typeConst: null }
              );
              lastInvokeResult = null;
            } else if (op === 0x12) {
              // const/4 vA, #+B
              const vA = (word0 >> 8) & 0x0f;
              let rawNibble = (word0 >> 12) & 0x0f;
              if (rawNibble >= 8) rawNibble -= 16;
              regs.set(vA, { taintSource: null, paramOrigins: [], callOriginIdx: null, strConst: null, numConst: rawNibble, typeConst: null });
              lastInvokeResult = null;
            } else if ((op === 0x13 || op === 0x14) && width >= 2) {
              // const/16 or const
              const vAA = (word0 >> 8) & 0xff;
              const numVal = op === 0x13
                ? dex.buffer.readInt16LE(insnsStart + (pc + 1) * 2)
                : dex.buffer.readInt32LE(insnsStart + (pc + 1) * 2);
              regs.set(vAA, { taintSource: null, paramOrigins: [], callOriginIdx: null, strConst: null, numConst: numVal, typeConst: null });
              lastInvokeResult = null;
            } else if ((op === 0x1a || op === 0x1b) && width >= 2) {
              // const-string / const-string/jumbo
              const vAA = (word0 >> 8) & 0xff;
              const strIdx = op === 0x1a
                ? dex.buffer.readUInt16LE(insnsStart + (pc + 1) * 2)
                : dex.buffer.readUInt32LE(insnsStart + (pc + 1) * 2);
              const sVal = reader.getString(strIdx);
              regs.set(vAA, { taintSource: null, paramOrigins: [], callOriginIdx: null, strConst: sVal, numConst: null, typeConst: 'Ljava/lang/String;' });
              lastInvokeResult = null;
            } else if (op === 0x22 && width >= 2) {
              // new-instance vAA, type@BBBB
              const vAA = (word0 >> 8) & 0xff;
              const typeIdx = dex.buffer.readUInt16LE(insnsStart + (pc + 1) * 2);
              regs.set(vAA, { taintSource: null, paramOrigins: [], callOriginIdx: null, strConst: null, numConst: null, typeConst: reader.getTypeDescriptor(typeIdx) });
              lastInvokeResult = null;
            } else if (op === 0x27) {
              hasThrow = true;
              lastInvokeResult = null;
            } else if (op === 0x0f || op === 0x10 || op === 0x11) {
              // return / return-wide / return-object
              const vAA = (word0 >> 8) & 0xff;
              const retState = getReg(vAA);
              if (opcodeCount <= 4 && retState.numConst === 1) returnedOneConstant = true;
              if (retState.taintSource && !methodSummary.returnsTaintSource) {
                methodSummary.returnsTaintSource = retState.taintSource;
              }
              for (const pIdx of retState.paramOrigins) {
                methodSummary.returnParamIndices.add(pIdx);
              }
              if (retState.callOriginIdx !== null && methodSummary.returnCallOrigins.length < 16) {
                methodSummary.returnCallOrigins.push(retState.callOriginIdx);
              }
              lastInvokeResult = null;
            } else if ((op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)) {
              // invoke-* (35c or 3rc)
              hasMeaningfulCall = true;
              const methodIdx = dex.buffer.readUInt16LE(insnsStart + (pc + 1) * 2);
              const argWord = dex.buffer.readUInt16LE(insnsStart + (pc + 2) * 2);
              const argRegs: number[] = [];

              if (op <= 0x72) {
                const argCount = (word0 >> 12) & 0x0f;
                const g = (word0 >> 8) & 0x0f;
                if (argCount >= 1) argRegs.push(argWord & 0x0f);
                if (argCount >= 2) argRegs.push((argWord >> 4) & 0x0f);
                if (argCount >= 3) argRegs.push((argWord >> 8) & 0x0f);
                if (argCount >= 4) argRegs.push((argWord >> 12) & 0x0f);
                if (argCount >= 5) argRegs.push(g);
              } else {
                const argCount = (word0 >> 8) & 0xff;
                for (let k = 0; k < Math.min(argCount, 8); k++) {
                  argRegs.push(argWord + k);
                }
              }

              const callee = reader.getMethodRef(methodIdx);
              const calleeClass = callee.classDesc;
              const calleeName = callee.name;

              if (
                calleeClass === 'Lokhttp3/CertificatePinner;' ||
                calleeClass === 'Lokhttp3/CertificatePinner$Builder;' ||
                calleeClass === 'Lcom/datatheorem/android/trustkit/TrustKit;' ||
                calleeName === 'setCertificatePinner'
              ) {
                if (pinningSignals.size < 8) {
                  pinningSignals.add(`${formatReadableClass(calleeClass)}.${calleeName}()`);
                }
              }

              const callCat = classifyCallCategory(calleeClass, calleeName);
              if (callCat) {
                addHotspot({
                  callerMethod: fullMethodSig,
                  calleeSignature: `${formatReadableClass(calleeClass)}.${calleeName}()`,
                  category: callCat
                });
              }

              // Track taint propagation & result origin cleanly (local sources + paramOrigins + interprocedural call return)
              const nextResult: RegisterState = { taintSource: null, paramOrigins: [], callOriginIdx: null, strConst: null, numConst: null, typeConst: null };
              const sourceLabel = classifyTaintSource(calleeClass, calleeName);
              if (sourceLabel) {
                nextResult.taintSource = sourceLabel;
              } else if (
                (calleeClass === 'Ljava/lang/StringBuilder;' || calleeClass === 'Ljava/lang/StringBuffer;') &&
                calleeName === 'append' &&
                argRegs.length >= 2
              ) {
                const baseState = getReg(argRegs[0]);
                const appendState = getReg(argRegs[1]);
                const propagated = appendState.taintSource || baseState.taintSource;
                if (propagated) {
                  baseState.taintSource = propagated;
                  nextResult.taintSource = propagated;
                }
                const mergedParams = mergeParamOrigins(baseState.paramOrigins, appendState.paramOrigins);
                baseState.paramOrigins = mergedParams;
                nextResult.paramOrigins = [...mergedParams];
                if (appendState.callOriginIdx !== null) {
                  baseState.callOriginIdx = appendState.callOriginIdx;
                  nextResult.callOriginIdx = appendState.callOriginIdx;
                } else if (baseState.callOriginIdx !== null) {
                  nextResult.callOriginIdx = baseState.callOriginIdx;
                }
              } else if (
                (calleeClass === 'Ljava/lang/StringBuilder;' || calleeClass === 'Ljava/lang/StringBuffer;') &&
                calleeName === 'toString' &&
                argRegs.length >= 1
              ) {
                const baseState = getReg(argRegs[0]);
                nextResult.taintSource = baseState.taintSource;
                nextResult.paramOrigins = [...baseState.paramOrigins];
                nextResult.callOriginIdx = baseState.callOriginIdx;
              } else if (
                (calleeClass === 'Landroid/net/Uri;' && calleeName === 'parse' && argRegs.length >= 1) ||
                (calleeClass === 'Ljava/lang/String;' && (calleeName === 'format' || calleeName === 'valueOf' || calleeName === 'concat' || calleeName === 'trim'))
              ) {
                for (const r of argRegs) {
                  const st = getReg(r);
                  if (st.taintSource && !nextResult.taintSource) nextResult.taintSource = st.taintSource;
                  if (st.paramOrigins.length > 0) nextResult.paramOrigins = mergeParamOrigins(nextResult.paramOrigins, st.paramOrigins);
                  if (st.callOriginIdx !== null && nextResult.callOriginIdx === null) nextResult.callOriginIdx = st.callOriginIdx;
                }
              } else if (calleeClass === 'Ljava/lang/String;' && calleeName === 'getBytes' && argRegs.length >= 1) {
                const strOrigin = getReg(argRegs[0]).strConst;
                if (strOrigin && strOrigin.length >= 4) {
                  nextResult.strConst = strOrigin;
                }
              } else if (
                calleeClass &&
                !isNoiseFrameworkClass(calleeClass, appPkgPrefix) &&
                callee.canonicalKey !== canonicalMethodKey &&
                methodSummary.calls.length < 40
              ) {
                const argInfos: ArgTaintOrigin[] = argRegs.map(r => {
                  const st = getReg(r);
                  return {
                    taintSource: st.taintSource,
                    paramOrigins: [...st.paramOrigins],
                    callOriginIdx: st.callOriginIdx
                  };
                });
                const callIdx = methodSummary.calls.length;
                methodSummary.calls.push({
                  calleeKey: callee.canonicalKey,
                  calleeReadableSig: `${formatReadableClass(calleeClass)}.${calleeName}()`,
                  argInfos
                });
                nextResult.callOriginIdx = callIdx;
              }

              lastInvokeResult = nextResult;

              // ── Security Sink Inspection ──
              // 1. Tainted WebView URL / JS execution
              if (
                calleeClass === 'Landroid/webkit/WebView;' &&
                (calleeName === 'loadUrl' || calleeName === 'loadData' || calleeName === 'loadDataWithBaseURL' || calleeName === 'evaluateJavascript')
              ) {
                const webViewSink: SinkHitTemplate = {
                  sinkName: `WebView.${calleeName}()`,
                  findingType: `Tainted WebView Load / JS Injection (${calleeName})`,
                  severity: 'HIGH',
                  owaspRef: 'MASVS-PLATFORM-1',
                  description: 'External Intent, deep-link URI, or clipboard data flows into a WebView without host/scheme sanitization, enabling phishing or JavaScript bridge abuse.',
                  remediation: 'Validate URL host against a strict HTTPS allowlist (e.g., uri.getHost().equals("yourdomain.com")) before calling loadUrl/evaluateJavascript.'
                };
                const taintedReg = argRegs.slice(1).find(r => getReg(r).taintSource);
                if (taintedReg !== undefined) {
                  const src = getReg(taintedReg).taintSource!;
                  taintPaths.push({
                    source: src,
                    sink: webViewSink.sinkName,
                    methodSignature: fullMethodSig,
                    detail: `Untrusted input from ${src} flows directly into ${webViewSink.sinkName} without domain allowlist validation inside ${fullMethodSig}.`,
                    severity: 'HIGH',
                    owaspRef: webViewSink.owaspRef,
                    hopCount: 1,
                    callChain: [fullMethodSig, webViewSink.sinkName]
                  });
                  addFinding({
                    category: 'Deep Bytecode Taint Graph',
                    type: webViewSink.findingType,
                    severity: 'HIGH',
                    proof: `Bytecode flow in ${fullMethodSig}: ${src} -> ${webViewSink.sinkName}`,
                    description: webViewSink.description,
                    remediation: webViewSink.remediation,
                    owaspRef: webViewSink.owaspRef
                  });
                } else {
                  recordUnresolvedParamOrCallSink(methodSummary, argRegs.slice(1), getReg, webViewSink);
                }
              }

              // 2. Tainted SQLite rawQuery / execSQL
              if (calleeClass === 'Landroid/database/sqlite/SQLiteDatabase;' && (calleeName === 'rawQuery' || calleeName === 'execSQL')) {
                const sqlSink: SinkHitTemplate = {
                  sinkName: `SQLiteDatabase.${calleeName}()`,
                  findingType: `Local SQLite Injection Sink (${calleeName})`,
                  severity: 'HIGH',
                  owaspRef: 'MASVS-STORAGE-1',
                  description: 'Untrusted Intent/URI data reaches a raw SQLite query or execSQL sink via string concatenation rather than bound parameters.',
                  remediation: 'Use parameterized queries with "?" selectionArgs or Room @Query bindings instead of dynamic SQL concatenation.'
                };
                const taintedReg = argRegs.slice(1).find(r => getReg(r).taintSource);
                if (taintedReg !== undefined) {
                  const src = getReg(taintedReg).taintSource!;
                  taintPaths.push({
                    source: src,
                    sink: sqlSink.sinkName,
                    methodSignature: fullMethodSig,
                    detail: `Tainted ${src} flows into ${sqlSink.sinkName} in ${fullMethodSig}.`,
                    severity: 'HIGH',
                    owaspRef: sqlSink.owaspRef,
                    hopCount: 1,
                    callChain: [fullMethodSig, sqlSink.sinkName]
                  });
                  addFinding({
                    category: 'Deep Bytecode Taint Graph',
                    type: sqlSink.findingType,
                    severity: 'HIGH',
                    proof: `Bytecode flow in ${fullMethodSig}: ${src} -> ${sqlSink.sinkName}`,
                    description: sqlSink.description,
                    remediation: sqlSink.remediation,
                    owaspRef: sqlSink.owaspRef
                  });
                } else {
                  recordUnresolvedParamOrCallSink(methodSummary, argRegs.slice(1), getReg, sqlSink);
                }
              }

              // 3. Tainted Runtime.exec / Command Injection
              if (calleeClass === 'Ljava/lang/Runtime;' && calleeName === 'exec') {
                const execSink: SinkHitTemplate = {
                  sinkName: 'Runtime.exec()',
                  findingType: 'Tainted OS Command Execution (Runtime.exec)',
                  severity: 'CRITICAL',
                  owaspRef: 'MASVS-CODE-1',
                  description: 'External data enters Runtime.exec(), allowing malicious callers or deep links to execute arbitrary shell commands.',
                  remediation: 'Eliminate shell invocation or restrict arguments strictly via an explicit allowlist.'
                };
                const taintedReg = argRegs.slice(1).find(r => getReg(r).taintSource);
                if (taintedReg !== undefined) {
                  const src = getReg(taintedReg).taintSource!;
                  taintPaths.push({
                    source: src,
                    sink: execSink.sinkName,
                    methodSignature: fullMethodSig,
                    detail: `Tainted ${src} flows into Runtime.exec() in ${fullMethodSig}.`,
                    severity: 'CRITICAL',
                    owaspRef: execSink.owaspRef,
                    hopCount: 1,
                    callChain: [fullMethodSig, execSink.sinkName]
                  });
                  addFinding({
                    category: 'Deep Bytecode Taint Graph',
                    type: execSink.findingType,
                    severity: 'CRITICAL',
                    proof: `Bytecode flow in ${fullMethodSig}: ${src} -> Runtime.exec()`,
                    description: execSink.description,
                    remediation: execSink.remediation,
                    owaspRef: execSink.owaspRef
                  });
                } else {
                  recordUnresolvedParamOrCallSink(methodSummary, argRegs.slice(1), getReg, execSink);
                }
              }

              // 4. Nested Intent Redirection
              if (
                (calleeName === 'startActivity' || calleeName === 'startActivityForResult' || calleeName === 'sendBroadcast' || calleeName === 'startService') &&
                argRegs.length >= 2
              ) {
                const intentSink: SinkHitTemplate = {
                  sinkName: `${calleeName}(Intent)`,
                  findingType: `Intent Redirection Vulnerability (${calleeName})`,
                  severity: 'HIGH',
                  owaspRef: 'MASVS-PLATFORM-1',
                  description: 'Forwarding an attacker-supplied nested Intent without validating its ComponentName allows external apps to launch private internal Activities or access protected ContentProviders.',
                  remediation: 'Verify intent.getComponent()?.getPackageName() === getPackageName() and sanitize flags (remove FLAG_GRANT_READ_URI_PERMISSION) before forwarding.'
                };
                const intentArgReg = argRegs[1];
                const intentSrc = getReg(intentArgReg).taintSource;
                if (intentSrc && (intentSrc.includes('getParcelableExtra') || intentSrc.includes('getIntent'))) {
                  taintPaths.push({
                    source: intentSrc,
                    sink: intentSink.sinkName,
                    methodSignature: fullMethodSig,
                    detail: `External ${intentSrc} forwarded directly into ${calleeName}() inside ${fullMethodSig}.`,
                    severity: 'HIGH',
                    owaspRef: intentSink.owaspRef,
                    hopCount: 1,
                    callChain: [fullMethodSig, intentSink.sinkName]
                  });
                  addFinding({
                    category: 'Deep Bytecode Taint Graph',
                    type: intentSink.findingType,
                    severity: 'HIGH',
                    proof: `Bytecode flow in ${fullMethodSig}: ${intentSrc} -> ${calleeName}()`,
                    description: intentSink.description,
                    remediation: intentSink.remediation,
                    owaspRef: intentSink.owaspRef
                  });
                } else {
                  recordUnresolvedParamOrCallSink(methodSummary, [intentArgReg], getReg, intentSink);
                }
              }

              // 5. Verified SslErrorHandler.proceed() in WebViewClient
              if (isWebViewClient && calleeClass === 'Landroid/webkit/SslErrorHandler;' && calleeName === 'proceed') {
                addFinding({
                  category: 'Deep Bytecode Audit (DEX)',
                  type: 'WebView SSL Error Ignored (SslErrorHandler.proceed)',
                  severity: 'CRITICAL',
                  proof: `Method ${fullMethodSig} explicitly calls SslErrorHandler.proceed() on TLS errors.`,
                  description: 'Calling handler.proceed() inside onReceivedSslError bypasses HTTPS certificate validation inside WebView, enabling trivial Man-in-the-Middle attacks.',
                  remediation: 'Replace handler.proceed() with handler.cancel() and abort loading on untrusted certificates.',
                  owaspRef: 'MASVS-NETWORK-1'
                });
              }

              // 6. Verified Weak Cipher in Method Bytecode
              if (calleeClass === 'Ljavax/crypto/Cipher;' && calleeName === 'getInstance' && argRegs.length >= 1) {
                const alg = getReg(argRegs[0]).strConst;
                if (alg && (/^(AES\/ECB|DES|DESede|RC4|Blowfish)/i.test(alg) || alg.toUpperCase() === 'AES')) {
                  addFinding({
                    category: 'Secrets & Cryptography',
                    type: `Weak Cipher Mode Verified in Method Bytecode (${alg})`,
                    severity: 'HIGH',
                    proof: `${fullMethodSig} invokes Cipher.getInstance("${alg}")`,
                    description: `Android JCA defaults "AES" to insecure ECB mode without authentication; "${alg}" leaks plaintext block patterns or uses weak 56-bit DES keys.`,
                    remediation: 'Use Cipher.getInstance("AES/GCM/NoPadding") with a random 12-byte IV via Android Keystore.',
                    owaspRef: 'MASVS-CRYPTO-1'
                  });
                }
              }

              // 7. Hardcoded SecretKeySpec Key or Static IvParameterSpec in Bytecode
              if (calleeClass === 'Ljavax/crypto/spec/SecretKeySpec;' && calleeName === '<init>' && argRegs.length >= 2) {
                const literalKey = getReg(argRegs[1]).strConst;
                if (literalKey && literalKey.length >= 4) {
                  addFinding({
                    category: 'Secrets & Cryptography',
                    type: 'Hardcoded Symmetric Key Passed to SecretKeySpec',
                    severity: 'HIGH',
                    proof: `${fullMethodSig} builds SecretKeySpec directly from hardcoded bytecode string literal ("${literalKey.slice(0, 4)}***").`,
                    description: 'Static encryption keys compiled into Dalvik bytecode allow any attacker using JADX to decrypt all local app secrets or tokens.',
                    remediation: 'Generate keys inside AndroidKeyStore using KeyGenerator instead of hardcoded string literals.',
                    owaspRef: 'MASVS-CRYPTO-1'
                  });
                }
              }

              if (calleeClass === 'Ljavax/crypto/spec/IvParameterSpec;' && calleeName === '<init>' && argRegs.length >= 2) {
                const literalIv = getReg(argRegs[1]).strConst;
                if (literalIv && literalIv.length >= 4) {
                  addFinding({
                    category: 'Secrets & Cryptography',
                    type: 'Static Hardcoded Initialization Vector (IvParameterSpec)',
                    severity: 'MEDIUM',
                    proof: `${fullMethodSig} initializes IvParameterSpec with constant bytecode literal.`,
                    description: 'Reusing a static IV destroys semantic security in CBC/GCM modes and enables chosen-plaintext analysis.',
                    remediation: 'Generate a fresh random IV with SecureRandom for every encryption operation.',
                    owaspRef: 'MASVS-CRYPTO-1'
                  });
                }
              }

              // 8. WebSettings + JavascriptInterface & File Access
              if (calleeClass === 'Landroid/webkit/WebSettings;') {
                if (calleeName === 'setJavaScriptEnabled' && argRegs.length >= 2 && getReg(argRegs[1]).numConst === 1) {
                  classEnabledJs = true;
                }
                if (
                  (calleeName === 'setAllowUniversalAccessFromFileURLs' || calleeName === 'setAllowFileAccessFromFileURLs') &&
                  argRegs.length >= 2 &&
                  getReg(argRegs[1]).numConst === 1
                ) {
                  addFinding({
                    category: 'Deep Bytecode Audit (DEX)',
                    type: `WebView Universal/File Cross-Origin Access Enabled (${calleeName})`,
                    severity: 'HIGH',
                    proof: `${fullMethodSig} passes true to WebSettings.${calleeName}(true).`,
                    description: 'Enabling file-based cross-origin access inside WebView lets malicious local HTML/JS files read arbitrary app-private files in /data/data/.',
                    remediation: `Call settings.${calleeName}(false) and migrate local assets to androidx.webkit.WebViewAssetLoader.`,
                    owaspRef: 'MASVS-PLATFORM-1'
                  });
                }
              }

              if (calleeClass === 'Landroid/webkit/WebView;' && calleeName === 'addJavascriptInterface') {
                classAddedJsBridge = true;
                jsBridgeMethod = fullMethodSig;
              }

              // 9. World-Readable / World-Writeable App Files
              if (
                calleeName === 'openFileOutput' &&
                argRegs.length >= 3 &&
                (getReg(argRegs[2]).numConst === 1 || getReg(argRegs[2]).numConst === 2)
              ) {
                const mode = getReg(argRegs[2]).numConst;
                addFinding({
                  category: 'Storage & Privacy',
                  type: `World-${mode === 1 ? 'Readable' : 'Writeable'} Private File Creation (openFileOutput)`,
                  severity: 'HIGH',
                  proof: `${fullMethodSig} calls openFileOutput(..., mode=${mode}).`,
                  description: 'Deprecated MODE_WORLD_READABLE/WRITEABLE lets any installed app read or overwrite private application files.',
                  remediation: 'Pass Context.MODE_PRIVATE (0) and share files safely via FileProvider.',
                  owaspRef: 'MASVS-STORAGE-1'
                });
              }

              // 10. Mutable PendingIntent (app package focused to avoid SDK noise)
              if (
                appPkgPrefix &&
                classDesc.startsWith(appPkgPrefix) &&
                calleeClass === 'Landroid/app/PendingIntent;' &&
                (calleeName === 'getActivity' || calleeName === 'getBroadcast' || calleeName === 'getService') &&
                argRegs.length >= 4
              ) {
                const flagsVal = getReg(argRegs[3]).numConst;
                // FLAG_IMMUTABLE = 0x04000000 (67108864); FLAG_MUTABLE = 0x02000000 (33554432)
                if (flagsVal !== null && (flagsVal & 0x04000000) === 0 && (flagsVal === 0 || (flagsVal & 0x02000000) !== 0)) {
                  addFinding({
                    category: 'Manifest & IPC Surface',
                    type: `Mutable PendingIntent Flag Used (${calleeName})`,
                    severity: 'MEDIUM',
                    proof: `${fullMethodSig} creates PendingIntent.${calleeName}(flags=${flagsVal}) without FLAG_IMMUTABLE.`,
                    description: 'Mutable PendingIntents can have their base Intent modified by third-party receivers to escalate privileges or redirect broadcasts.',
                    remediation: 'Add PendingIntent.FLAG_IMMUTABLE unless mutable inline reply/bubbles strictly require FLAG_MUTABLE.',
                    owaspRef: 'MASVS-PLATFORM-1'
                  });
                }
              }
            } else {
              lastInvokeResult = null;
            }

            pc += width;
          }

          // Check structural SSL bypass interfaces at method completion
          if (isTrustManager && methodName === 'checkServerTrusted' && !hasThrow && (!hasMeaningfulCall || opcodeCount <= 2)) {
            addFinding({
              category: 'Deep Bytecode Audit (DEX)',
              type: 'Empty X509TrustManager Certificate Check Verified in Bytecode',
              severity: 'CRITICAL',
              proof: `${fullMethodSig} implements X509TrustManager with no certificate verification or CertificateException throw (${opcodeCount} Dalvik instructions).`,
              description: 'An empty checkServerTrusted() implementation accepts every forged or attacker-controlled TLS certificate, exposing 100% of HTTPS traffic to MitM interception.',
              remediation: 'Delete custom permissive TrustManager classes and use Android system TrustManager / Network Security Config + OkHttp CertificatePinner.',
              owaspRef: 'MASVS-NETWORK-1'
            });
          }

          if (isHostnameVerifier && methodName === 'verify' && returnedOneConstant && opcodeCount <= 4) {
            addFinding({
              category: 'Deep Bytecode Audit (DEX)',
              type: 'Permissive HostnameVerifier (Always Returns True) Verified in Bytecode',
              severity: 'CRITICAL',
              proof: `${fullMethodSig} unconditionally returns true (${opcodeCount} Dalvik instructions), disabling TLS hostname checks.`,
              description: 'Returning true in HostnameVerifier.verify() lets any valid certificate from any unrelated domain impersonate your backend API.',
              remediation: 'Remove custom HostnameVerifier overrides and rely on HttpsURLConnection.getDefaultHostnameVerifier().',
              owaspRef: 'MASVS-NETWORK-1'
            });
          }
          if (
            methodSummary.directParamSinks.size > 0 ||
            methodSummary.localCallSinks.length > 0 ||
            methodSummary.returnsTaintSource !== null ||
            methodSummary.returnParamIndices.size > 0 ||
            methodSummary.returnCallOrigins.length > 0 ||
            methodSummary.calls.length > 0
          ) {
            methodSummaries.set(methodSummary.key, methodSummary);
          }
        }

        if (mSection === 0 && totalClassMethods > 400) break;
      }

      const isHybridEngineRuntime =
        classDesc.startsWith('Lcom/getcapacitor/') ||
        classDesc.startsWith('Lcom/capacitorjs/') ||
        classDesc.startsWith('Lorg/apache/cordova/') ||
        classDesc.startsWith('Lcom/facebook/react/') ||
        classDesc.startsWith('Lio/flutter/');

      if (classEnabledJs && classAddedJsBridge && !isHybridEngineRuntime) {
        addFinding({
          category: 'Deep Bytecode Audit (DEX)',
          type: 'WebView JavaScript Bridge Registered (setJavaScriptEnabled + addJavascriptInterface)',
          severity: 'MEDIUM',
          proof: `Class ${readableClass} enables JavaScript and binds native bridge via addJavascriptInterface() in ${jsBridgeMethod}.`,
          description: 'Combining setJavaScriptEnabled(true) with @JavascriptInterface exposes native Kotlin/Java methods to whatever webpage loads inside the WebView.',
          remediation: 'Restrict WebView navigation to trusted HTTPS origins and expose minimal @JavascriptInterface methods (targetSdk >= 17).',
          owaspRef: 'MASVS-PLATFORM-1'
        });
      }
    }
  }

  // ── Phase 2 & 3: Cross-Method Global Taint Propagation (2-4 Hop Call Chains) ──
  const interproceduralPathsCount = resolveInterproceduralTaint(methodSummaries, taintPaths, addFinding);

  return {
    summary: {
      dexCount: dexFiles.length,
      totalClasses,
      appClasses,
      methodsAnalyzed,
      instructionsScanned,
      durationMs: Date.now() - startTime,
      interproceduralPathsCount,
      pinningSignals: Array.from(pinningSignals),
      taintPaths: taintPaths.slice(0, 20),
      callGraphHotspots: Array.from(hotspotMap.values()).slice(0, 15)
    },
    findings
  };
}

function resolveInterproceduralTaint(
  methodSummaries: Map<string, MethodSummary>,
  taintPaths: TaintFlowFinding[],
  addFinding: (f: DexBytecodeFinding) => void
): number {
  const MAX_HOPS = 4;
  const effectiveReturnSource = new Map<string, { source: string; chain: string[] }>();
  for (const [k, m] of methodSummaries.entries()) {
    if (m.returnsTaintSource) {
      effectiveReturnSource.set(k, { source: m.returnsTaintSource, chain: [m.readableSig] });
    }
  }

  const effectiveParamSinks = new Map<string, Map<number, Array<{ sink: SinkHitTemplate; chain: string[] }>>>();
  for (const [k, m] of methodSummaries.entries()) {
    if (m.directParamSinks.size > 0) {
      const pMap = new Map<number, Array<{ sink: SinkHitTemplate; chain: string[] }>>();
      for (const [pIdx, sinks] of m.directParamSinks.entries()) {
        pMap.set(pIdx, sinks.map(sink => ({ sink, chain: [m.readableSig] })));
      }
      effectiveParamSinks.set(k, pMap);
    }
  }

  const resolveCallResultTaint = (
    m: MethodSummary,
    callIdx: number
  ): { source: string; chain: string[] } | null => {
    const call = m.calls[callIdx];
    if (!call) return null;
    const directRet = effectiveReturnSource.get(call.calleeKey);
    if (directRet) return directRet;

    // Also propagate pass-through helpers (e.g., sanitizeWrapper(taintedInput))
    const calleeSum = methodSummaries.get(call.calleeKey);
    if (!calleeSum || calleeSum.returnParamIndices.size === 0) return null;
    for (const pIdx of calleeSum.returnParamIndices) {
      const arg = call.argInfos[pIdx];
      if (!arg) continue;
      if (arg.taintSource) {
        return { source: arg.taintSource, chain: [calleeSum.readableSig] };
      }
      if (arg.callOriginIdx !== null) {
        const inner = m.calls[arg.callOriginIdx];
        const innerRet = inner ? effectiveReturnSource.get(inner.calleeKey) : undefined;
        if (innerRet && innerRet.chain.length < MAX_HOPS && !innerRet.chain.includes(calleeSum.readableSig)) {
          return { source: innerRet.source, chain: [...innerRet.chain, calleeSum.readableSig] };
        }
      }
    }
    return null;
  };

  // Fixed-point propagation across up to 4 hops
  for (let pass = 0; pass < MAX_HOPS; pass++) {
    let changed = false;

    for (const [k, m] of methodSummaries.entries()) {
      if (!effectiveReturnSource.has(k)) {
        for (const callIdx of m.returnCallOrigins) {
          const ret = resolveCallResultTaint(m, callIdx);
          if (ret && ret.chain.length < MAX_HOPS && !ret.chain.includes(m.readableSig)) {
            effectiveReturnSource.set(k, {
              source: ret.source,
              chain: [...ret.chain, m.readableSig]
            });
            changed = true;
            break;
          }
        }
      }

      for (const call of m.calls) {
        const calleeSinks = effectiveParamSinks.get(call.calleeKey);
        if (!calleeSinks) continue;

        for (let argIdx = 0; argIdx < call.argInfos.length; argIdx++) {
          const arg = call.argInfos[argIdx];
          if (arg.paramOrigins.length === 0) continue;
          const targetEntries = calleeSinks.get(argIdx);
          if (!targetEntries) continue;

          for (const entry of targetEntries) {
            if (entry.chain.length >= MAX_HOPS || entry.chain.includes(m.readableSig)) continue;
            let callerMap = effectiveParamSinks.get(k);
            if (!callerMap) {
              callerMap = new Map();
              effectiveParamSinks.set(k, callerMap);
            }
            for (const callerParamIdx of arg.paramOrigins) {
              const list = callerMap.get(callerParamIdx) || [];
              if (!list.some(item => item.sink.sinkName === entry.sink.sinkName)) {
                list.push({ sink: entry.sink, chain: [m.readableSig, ...entry.chain] });
                callerMap.set(callerParamIdx, list);
                changed = true;
              }
            }
          }
        }
      }
    }

    if (!changed) break;
  }

  let interproceduralCount = 0;
  const dedupChains = new Set<string>();

  const emitCrossMethodFlow = (
    resolvedSource: string,
    callChain: string[],
    sink: SinkHitTemplate,
    entryMethod: string
  ) => {
    if (sink.sinkName.endsWith('(Intent)') && !resolvedSource.includes('getParcelableExtra') && !resolvedSource.includes('getIntent')) {
      return;
    }
    const hops = Math.max(2, callChain.length - 1);
    const dedupKey = `${sink.sinkName}::${callChain.join('->')}`;
    if (dedupChains.has(dedupKey) || taintPaths.length >= 20) return;
    dedupChains.add(dedupKey);
    interproceduralCount++;

    const flowText = callChain.join(' -> ');
    taintPaths.push({
      source: resolvedSource,
      sink: sink.sinkName,
      methodSignature: entryMethod,
      detail: `Cross-method ${hops}-hop flow (${resolvedSource}): ${flowText}`,
      severity: sink.severity,
      owaspRef: sink.owaspRef,
      hopCount: hops,
      callChain
    });
    addFinding({
      category: 'Deep Bytecode Taint Graph',
      type: `Cross-Method Global Taint Flow: ${sink.findingType}`,
      severity: sink.severity,
      proof: `Multi-hop flow (${hops} hops, Source: ${resolvedSource}): ${flowText}`,
      description: `Untrusted input travels across multiple classes/methods (${hops} call hops) before reaching ${sink.sinkName} without host or parameter sanitization.`,
      remediation: sink.remediation,
      owaspRef: sink.owaspRef
    });
  };

  for (const m of methodSummaries.values()) {
    // Pattern A: Helper method returned untrusted taint into a direct sink inside caller m
    for (const localSink of m.localCallSinks) {
      const ret = resolveCallResultTaint(m, localSink.callOriginIdx);
      if (ret) {
        emitCrossMethodFlow(ret.source, [...ret.chain, m.readableSig, localSink.sink.sinkName], localSink.sink, m.readableSig);
      }
    }

    // Pattern B: Caller m obtains untrusted taint (directly or via helper return) and passes it down a 2-4 hop param-to-sink chain
    for (const call of m.calls) {
      const calleeSinks = effectiveParamSinks.get(call.calleeKey);
      if (!calleeSinks) continue;

      for (let argIdx = 0; argIdx < call.argInfos.length; argIdx++) {
        const targetEntries = calleeSinks.get(argIdx);
        if (!targetEntries) continue;

        const arg = call.argInfos[argIdx];
        let srcLabel: string | null = arg.taintSource;
        let prefixChain: string[] = [m.readableSig];

        if (!srcLabel && arg.callOriginIdx !== null) {
          const ret = resolveCallResultTaint(m, arg.callOriginIdx);
          if (ret) {
            srcLabel = ret.source;
            prefixChain = [...ret.chain, m.readableSig];
          }
        }
        if (!srcLabel) continue;

        for (const entry of targetEntries) {
          if (entry.chain.includes(m.readableSig)) continue;
          const fullChain = [...prefixChain, ...entry.chain, entry.sink.sinkName];
          emitCrossMethodFlow(srcLabel, fullChain, entry.sink, m.readableSig);
        }
      }
    }
  }

  return interproceduralCount;
}
