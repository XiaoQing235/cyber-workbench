import { OperationRegistry } from "../core/operation/registry";
import type { OperationDefinition } from "../core/operation/types";
import { midiInspect, midiNoteBytes } from "./audio/midi";
import { wavInspect, wavSpectrogram, wavSpectrum } from "./audio/wav";
import { ffmpegAudioWav } from "./audio/ffmpeg";
import { autoDecode } from "./analysis/autoDecode";
import { carveScan } from "./analysis/carve";
import { fileDetect } from "./analysis/detect";
import { stringsExtract } from "./analysis/strings";
import { badByteXorKeys, bitsReverse, bytesNot, bytesReverse, bytesSlice, bytesXor } from "./binary/bytes";
import { structCodegen, structParse, structSetField } from "./binary/struct";
import { sqliteFreePages, sqliteInspect, sqliteQuery, sqliteValue } from "./database/sqlite";
import { disasm } from "./reverse/disasm";
import { dotnetInspect, dotnetString } from "./reverse/dotnet";
import { il2cppInspect, il2cppLiteralExtract, il2cppLiterals } from "./reverse/il2cpp";
import { seccompInspect } from "./reverse/seccomp";
import { formatStringWrites } from "./reverse/formatString";
import { ropFilter } from "./reverse/rop";
import { uxnAuxinInspect } from "./reverse/uxnAuxin";
import { apkDexExtract, apkInspect } from "./reverse/androidApk";
import { asarExtract, asarInspect } from "./reverse/asar";
import { godotPckExtract, godotPckInspect } from "./reverse/godotPck";
import { unrealPakExtract, unrealPakInspect, unrealPakList } from "./reverse/unrealPak";
import { renpyIndexExtract, renpyInspect, renpyMemberExtract, renpyMembersInspect } from "./reverse/renpy";
import { dexInspect } from "./reverse/dex";
import { jarExtract, jarInspect } from "./reverse/javaArchive";
import { luaBytecodeInspect } from "./reverse/luaBytecode";
import { pythonBytecodeInspect, pythonMarshalExtract } from "./reverse/pythonBytecode";
import { pyInstallerExtract, pyInstallerInspect, pyInstallerPycRebuild } from "./reverse/pyInstaller";
import { pythonRun } from "./code/python";
import { zlibInflate } from "./compression/zlib";
import { credentialHashIdentify } from "./crypto/credentials";
import { evmAbiParameters, evmCreate2, evmRlpDecode, evmRlpEncode, evmSelector, evmStorageSlot, evmTypedDataHash } from "./crypto/evm";
import { passwordCandidatesGenerate } from "./crypto/candidates";
import { passwordCandidatesVerify } from "./crypto/passwordVerify";
import { keepassHashExport, keepassInspect } from "./crypto/keepass";
import { nonceReuseCrib, nonceReuseInspect, nonceReuseXor } from "./crypto/nonce";
import { quarterRoundPrefixRecover } from "./crypto/oneQuarterRound";
import { oracleTranscriptAnalyze, paddingOracleSimulate } from "./crypto/oracle";
import { pdfEncryptionInspect, pdfHashExport } from "./crypto/pdf";
import { lcgRecover, lcgRsaReconstruct, lcgUnknownRecover, lcgXorTranscript, mt19937Recover } from "./crypto/prng";
import { rsaPublicKeyInspect } from "./crypto/rsaPublicKey";
import { graphHamiltonianCandidate } from "./crypto/graph";
import { agePassphraseDecrypt } from "./crypto/agePassphrase";
import { npcPasswordsDiscover } from "./crypto/npcDiscovery";
import { npcHintVerify } from "./crypto/npcHint";
import { continuedFractionExpand } from "./crypto/continuedFraction";
import { colorContrastIsolate, colorContrastTextStrip } from "./image/colorContrast";
import { symatrixDecode } from "./image/symatrix";
import { primesMessageRecover } from "./crypto/primesMessage";
import { sshPrivateKeyInspect, sshPrivateKeyJohnExport } from "./crypto/ssh";
import { base64Decode, base64Encode } from "./encoding/base64";
import { hexDecode, hexEncode } from "./encoding/hex";
import { gitCat, gitInspect, gitShow } from "./forensics/git";
import { ipaExtract, ipaInspect } from "./forensics/iosIpa";
import { kubernetesManifestsInspect } from "./forensics/kubernetes";
import { rar5HashExport, rar7zInspect, sevenZipHashExport, zipCrc32FourByte, zipEndChainRecover, zipExtract, zipExtractKeys, zipHashExport, zipHashRestore, zipInspect, zipKnownPlaintext, zipPasswordTest, zipPlainExtract, zipPolyglotCompose, zipRebuild } from "./forensics/archive";
import { sevenZipCopyExtract, sevenZipCopyInspect } from "./forensics/sevenZipCopy";
import { safeTensorExtract, safeTensorsInspect } from "./forensics/safeTensors";
import { tensorBitsExtract } from "./forensics/tensorBits";
import { onnxInspect, onnxTensorExtract } from "./forensics/onnx";
import { onnxTensorBits } from "./forensics/onnxBits";
import { browserHistoryInspect, browserHistoryTimelineExport } from "./forensics/browserHistory";
import { cloudTrailInspect, cloudTrailRoleGraph, cloudTrailTimelineExport } from "./forensics/cloudTrail";
import { cloudTrailEntitiesExport } from "./forensics/cloudTrailEntities";
import { entityCorrelate } from "./forensics/entityCorrelation";
import { evtxBinXmlExtract, evtxInspect, evtxTimelineExport } from "./forensics/evtx";
import { evtxSubstitutionsInspect } from "./forensics/evtxSubstitutions";
import { evtxSubstitutionExtract } from "./forensics/evtxSubstitutionExtract";
import { evtxNestedSubstitutionsInspect } from "./forensics/evtxNestedSubstitutions";
import { evtxNestedExtract } from "./forensics/evtxNestedExtract";
import { evtxInlineNamesInspect } from "./forensics/evtxInlineNames";
import { eseHeaderInspect } from "./forensics/eseHeader";
import { diskPartitionsInspect } from "./forensics/disk";
import { fat32DeletedCandidate, fat32Extract, fat32Inspect } from "./forensics/fat32";
import { lnkInspect, lnkTimelineExport } from "./forensics/lnk";
import { mailAttachmentExtract, mailInspect } from "./forensics/mail";
import { ntfsDeletedNonResidentCandidate, ntfsDeletedResidentCandidate, ntfsMacbTimelineExport, ntfsRecordInspect, ntfsStreamExtract } from "./forensics/ntfs";
import { pickleOpcodesInspect } from "./forensics/pickle";
import { prefetchInspect, prefetchTimelineExport } from "./forensics/prefetch";
import { registryHiveInspect, registryHiveTimelineExport, registryHiveValueDecode, registryHiveValueExtract } from "./forensics/registryHive";
import { ociImageExtract, ociImageInspect, ociLayerInspect } from "./forensics/ociLayer";
import { officeEncryptionInspect, officeHashExport } from "./forensics/office";
import { scriptUnpack } from "./forensics/script";
import { terraformStateInspect } from "./forensics/terraform";
import { timelineImport } from "./forensics/timeline";
import { crc32, hashDigest } from "./hash/hash";
import { vcdCanDecode, vcdI2cDecode, vcdInspect, vcdManchesterDecode, vcdNrzDecode, vcdSpiDecode, vcdUartDecode } from "./hardware/vcd";
import { dtmfDecode } from "./hardware/dtmf";
import { morseDecode } from "./hardware/morse";
import { sstvVisDecode } from "./hardware/sstv";
import { iqSpectrum } from "./hardware/iq";
import { engraverServoTrace } from "./hardware/engraver";
import { saleaeDigitalImport, sigrokDigitalImport } from "./hardware/saleae";
import { sigrokSessionImport } from "./hardware/sigrokSession";
import { bmpInspect, bmpSetDimensions } from "./image/bmp";
import { apngFrameExport, apngFramesInspect } from "./image/apng";
import { webpFrameExport, webpFramesInspect } from "./image/webp";
import { gifFrameExport, gifFramesCompare, gifFramesInspect, gifTimelineInspect } from "./image/gif";
import { imageLsb } from "./image/lsb";
import { pixelPermutationImprove } from "./image/pixelPermutation";
import { pixelPermutationReplay } from "./image/permutationReplay";
import { ocrRecognize } from "./image/ocr";
import { pngFindDimensions, pngFixCrcs, pngInspect, pngSetIhdr } from "./image/png";
import { qrDecode, qrDrawGrid, qrFromGrid, qrToGrid } from "./image/qr";
import { pcapDnsNames, pcapHttpBody, pcapIcmpData, pcapInspect, pcapTcpStream } from "./network/pcap";
import { stormPylonMap } from "./network/storm";
import { pcapDeepInspect } from "./network/wiregasm";
import { harDiff } from "./network/har";
import { harHeaderDiff } from "./network/harHeaders";
import { burpDiff } from "./network/burp";
import { burpHeaderDiff } from "./network/burpHeaders";
import { timelineEntitiesExport } from "./forensics/timelineEntities";
import { rar4StoredExtract, rar5StoredExtract } from "./forensics/rar4Stored";
import { usbKeyboard, usbMouse } from "./network/usb";
import { textDecode, textEncode } from "./text/charset";
import { png2Decode } from "./reverse/png2";
import { unityBundleInspect, unityTextAssetExtract } from "./reverse/unityBundle";
import { whitespaceExtract } from "./text/whitespace";

export const builtinOperations: readonly OperationDefinition[] = [
  fileDetect,
  midiInspect,
  midiNoteBytes,
  wavInspect,
  ffmpegAudioWav,
  wavSpectrum,
  wavSpectrogram,
  carveScan,
  stringsExtract,
  autoDecode,
  base64Encode,
  base64Decode,
  hexEncode,
  hexDecode,
  textEncode,
  textDecode,
  whitespaceExtract,
  bytesReverse,
  bitsReverse,
  bytesNot,
  bytesXor,
  badByteXorKeys,
  bytesSlice,
  structParse,
  structSetField,
  structCodegen,
  hashDigest,
  crc32,
  vcdInspect,
  vcdCanDecode,
  vcdUartDecode,
  vcdSpiDecode,
  vcdI2cDecode,
  vcdManchesterDecode,
  vcdNrzDecode,
  dtmfDecode,
  morseDecode,
  sstvVisDecode,
  iqSpectrum,
  engraverServoTrace,
  png2Decode,
  unityBundleInspect,
  unityTextAssetExtract,
  saleaeDigitalImport,
  sigrokDigitalImport,
  sigrokSessionImport,
  zlibInflate,
  credentialHashIdentify,
  evmSelector,
  evmCreate2,
  evmRlpEncode,
  evmAbiParameters,
  evmTypedDataHash,
  evmStorageSlot,
  evmRlpDecode,
  passwordCandidatesGenerate,
  passwordCandidatesVerify,
  keepassInspect,
  keepassHashExport,
  nonceReuseInspect,
  nonceReuseXor,
  nonceReuseCrib,
  paddingOracleSimulate,
  oracleTranscriptAnalyze,
  lcgRecover,
  graphHamiltonianCandidate,
  npcHintVerify,
  npcPasswordsDiscover,
  agePassphraseDecrypt,
  continuedFractionExpand,
  colorContrastIsolate,
  colorContrastTextStrip,
  symatrixDecode,
  primesMessageRecover,
  lcgUnknownRecover,
  lcgXorTranscript,
  lcgRsaReconstruct,
  rsaPublicKeyInspect,
  quarterRoundPrefixRecover,
  mt19937Recover,
  pdfEncryptionInspect,
  pdfHashExport,
  sshPrivateKeyInspect,
  sshPrivateKeyJohnExport,
  pngInspect,
  pngSetIhdr,
  pngFixCrcs,
  pngFindDimensions,
  bmpInspect,
  bmpSetDimensions,
  apngFramesInspect,
  apngFrameExport,
  webpFramesInspect,
  webpFrameExport,
  gifFramesInspect,
  gifTimelineInspect,
  gifFrameExport,
  gifFramesCompare,
  imageLsb,
  pixelPermutationImprove,
  pixelPermutationReplay,
  qrDecode,
  qrToGrid,
  qrFromGrid,
  qrDrawGrid,
  ocrRecognize,
  pcapInspect,
  stormPylonMap,
  pcapDeepInspect,
  harDiff,
  harHeaderDiff,
  burpDiff,
  burpHeaderDiff,
  timelineEntitiesExport,
  rar4StoredExtract,
  rar5StoredExtract,
  pcapTcpStream,
  pcapHttpBody,
  pcapDnsNames,
  pcapIcmpData,
  usbKeyboard,
  usbMouse,
  rar7zInspect,
  sevenZipCopyInspect,
  sevenZipCopyExtract,
  rar5HashExport,
  sevenZipHashExport,
  browserHistoryInspect,
  browserHistoryTimelineExport,
  cloudTrailInspect,
  cloudTrailTimelineExport,
  cloudTrailRoleGraph,
  cloudTrailEntitiesExport,
  entityCorrelate,
  evtxInspect,
  evtxTimelineExport,
  evtxBinXmlExtract,
  evtxSubstitutionsInspect,
  evtxSubstitutionExtract,
  evtxNestedSubstitutionsInspect,
  evtxNestedExtract,
  evtxInlineNamesInspect,
  eseHeaderInspect,
  diskPartitionsInspect,
  fat32Inspect,
  fat32Extract,
  fat32DeletedCandidate,
  lnkInspect,
  lnkTimelineExport,
  mailInspect,
  mailAttachmentExtract,
  ntfsRecordInspect,
  ntfsMacbTimelineExport,
  ntfsStreamExtract,
  ntfsDeletedResidentCandidate,
  ntfsDeletedNonResidentCandidate,
  pickleOpcodesInspect,
  prefetchInspect,
  prefetchTimelineExport,
  registryHiveInspect,
  registryHiveTimelineExport,
  registryHiveValueExtract,
  registryHiveValueDecode,
  ociLayerInspect,
  ociImageInspect,
  ociImageExtract,
  officeEncryptionInspect,
  officeHashExport,
  zipInspect,
  zipPolyglotCompose,
  zipEndChainRecover,
  zipPlainExtract,
  zipCrc32FourByte,
  zipRebuild,
  zipPasswordTest,
  zipKnownPlaintext,
  zipHashExport,
  zipHashRestore,
  zipExtract,
  zipExtractKeys,
  gitInspect,
  gitShow,
  gitCat,
  ipaInspect,
  ipaExtract,
  kubernetesManifestsInspect,
  safeTensorsInspect,
  onnxInspect,
  onnxTensorExtract,
  onnxTensorBits,
  safeTensorExtract,
  tensorBitsExtract,
  timelineImport,
  terraformStateInspect,
  scriptUnpack,
  sqliteInspect,
  sqliteQuery,
  sqliteValue,
  sqliteFreePages,
  disasm,
  dotnetInspect,
  dotnetString,
  il2cppInspect,
  il2cppLiterals,
  il2cppLiteralExtract,
  seccompInspect,
  formatStringWrites,
  ropFilter,
  uxnAuxinInspect,
  apkInspect,
  apkDexExtract,
  asarInspect,
  asarExtract,
  godotPckInspect,
  godotPckExtract,
  unrealPakInspect,
  unrealPakList,
  unrealPakExtract,
  renpyInspect,
  renpyIndexExtract,
  renpyMembersInspect,
  renpyMemberExtract,
  dexInspect,
  jarInspect,
  jarExtract,
  luaBytecodeInspect,
  pythonBytecodeInspect,
  pythonMarshalExtract,
  pyInstallerInspect,
  pyInstallerExtract,
  pyInstallerPycRebuild,
  pythonRun,
];

export function createDefaultRegistry(): OperationRegistry {
  const registry = new OperationRegistry();
  for (const operation of builtinOperations) registry.register(operation);
  return registry;
}
