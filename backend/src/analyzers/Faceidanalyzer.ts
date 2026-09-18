import fs from 'fs'
import path from 'path'
import { logger } from '../utils/logger'

// ─────────────────────────────────────────────────────────────────────────────
//  Types
// ─────────────────────────────────────────────────────────────────────────────

export type BiometricType =
  | 'FACE_ID'
  | 'FINGERPRINT'
  | 'IRIS'
  | 'VOICE'
  | 'BEHAVIOR'
  | 'LIVENESS'
  | 'DOCUMENT_SCAN'
  | 'MULTI_MODAL'

export type FrameworkCategory =
  | 'NATIVE_OS'   
  | 'THIRD_PARTY'
  | 'KYC'       
  | 'COMMERCIAL'
  | 'CLOUD_API'
  | 'ENTERPRISE'
  | 'STANDARD'
  | 'HARDWARE'

export type ConfidenceLevel = 'HIGH' | 'MEDIUM' | 'LOW'

export interface FrameworkEvidence {
  file: string
  line: number
  snippet: string
  matchedPattern: string
}

export interface DetectedFramework {
  name: string
  version?: string
  vendor?: string
  biometricTypes: BiometricType[]
  platform: 'ANDROID' | 'IOS' | 'CROSS_PLATFORM'
  category: FrameworkCategory
  pricingModel?: 'FREE' | 'FREEMIUM' | 'COMMERCIAL' | 'ENTERPRISE' | 'OPEN_SOURCE'
  confidence: ConfidenceLevel
  reference?: string
  notes?: string
  evidence: FrameworkEvidence[]
  signalCount: number
}

export interface FaceIdAnalysisResult {
  hasBiometrics: boolean
  detectedFrameworks: DetectedFramework[]
  biometricTypes: BiometricType[]
  scannedFiles: number
  summary: AnalysisSummary
}

export interface AnalysisSummary {
  byCategory: Record<FrameworkCategory, string[]>
  totalFrameworks: number
  hasKycSdk: boolean
  hasCommercialSdk: boolean
  hasCloudApi: boolean
  hasEnterpriseGrade: boolean
  hasNativeOnly: boolean
}

// ─────────────────────────────────────────────────────────────────────────────
//  Internal signature shape
// ─────────────────────────────────────────────────────────────────────────────

interface FrameworkSignature {
  name: string
  vendor?: string
  biometricTypes: BiometricType[]
  platform: 'ANDROID' | 'IOS' | 'CROSS_PLATFORM'
  category: FrameworkCategory
  pricingModel?: DetectedFramework['pricingModel']
  reference?: string
  notes?: string

  codePatterns: RegExp[]

  depPatterns?: RegExp[]

  minSignals?: number
}

// ─────────────────────────────────────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────────────────────────────────────

const MIN_SIGNALS = 2
const MAX_FILE_BYTES = 3 * 1024 * 1024

const SCAN_EXTENSIONS = new Set([
  '.js', '.plist', '.java', '.so'])

const SKIP_DIRS = new Set([
  'node_modules', '.git', '__pycache__', 'build', 'DerivedData',
  '.gradle', 'Pods', '.idea', 'dist', 'out',
])

const DEP_FILENAMES = new Set([
  'package.json', 'package-lock.json',
  'podfile', 'podfile.lock',
  'pubspec.yaml', 'pubspec.yml',
  'build.gradle', 'build.gradle.kts',
  'settings.gradle', 'settings.gradle.kts',
  'gemfile', 'gemfile.lock',
])

// ─────────────────────────────────────────────────────────────────────────────
//  Signature catalogue
// ─────────────────────────────────────────────────────────────────────────────

const SIGNATURES: FrameworkSignature[] = [

  // ══════════════════════════════════════════════════════════════════════════
  //  NATIVE OS — iOS
  // ══════════════════════════════════════════════════════════════════════════

  {
    name: 'LocalAuthentication',
    vendor: 'Apple',
    biometricTypes: ['FACE_ID', 'FINGERPRINT'],
    platform: 'IOS',
    category: 'NATIVE_OS',
    pricingModel: 'FREE',
    reference: 'https://developer.apple.com/documentation/localauthentication',
    notes: 'Framework nativo de Apple para Face ID y Touch ID. Disponible desde iOS 8.',
    codePatterns: [
      /import\s+LocalAuthentication/,
      /LAContext\s*\(\)/,
      /evaluatePolicy\s*\(/,
      /canEvaluatePolicy\s*\(/,
      /LAPolicyDeviceOwnerAuthentication/,
      /LABiometryTypeFaceID/,
      /LABiometryTypeTouchID/,
      /LABiometryTypeOpticID/,
      /LAErrorBiometryNotAvailable/,
      /LAErrorAuthenticationFailed/,
      /localizedFallbackTitle/,
    ],
  },

  {
    name: 'AuthenticationServices',
    vendor: 'Apple',
    biometricTypes: ['FACE_ID', 'FINGERPRINT'],
    platform: 'IOS',
    category: 'NATIVE_OS',
    pricingModel: 'FREE',
    reference: 'https://developer.apple.com/documentation/authenticationservices',
    notes: 'Framework de Apple para Passkeys, Sign in with Apple y credenciales de plataforma (iOS 12+).',
    codePatterns: [
      /import\s+AuthenticationServices/,
      /ASAuthorizationController/,
      /ASAuthorizationAppleIDProvider/,
      /ASAuthorizationPlatformPublicKeyCredentialProvider/,
      /ASPasskeyCredentialRequest/,
      /performRequests\s*\(/,
    ],
  },

  {
    name: 'Secure Enclave (iOS)',
    vendor: 'Apple',
    biometricTypes: ['FACE_ID', 'FINGERPRINT'],
    platform: 'IOS',
    category: 'HARDWARE',
    pricingModel: 'FREE',
    reference: 'https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/protecting_keys_with_the_secure_enclave',
    notes: 'Chip T2/Secure Enclave para claves criptográficas ligadas a biometría.',
    minSignals: 1,
    codePatterns: [
      /kSecAttrTokenIDSecureEnclave/,
      /SecureEnclave\.P256/,
      /SecureEnclave\.Key/,
      /kSecAccessControlBiometryAny/,
      /kSecAccessControlBiometryCurrentSet/,
      /kSecAccessControlUserPresence/,
      /SecAccessControlCreateWithFlags/,
      /kSecUseAuthenticationContext/,
      /SecKeyCreateRandomKey/,
    ],
  },

  {
    name: 'Vision Framework (Face)',
    vendor: 'Apple',
    biometricTypes: ['FACE_ID', 'LIVENESS'],
    platform: 'IOS',
    category: 'NATIVE_OS',
    pricingModel: 'FREE',
    reference: 'https://developer.apple.com/documentation/vision',
    notes: 'Computer Vision de Apple para detección y tracking de rostros. On-device, no autenticación directa.',
    codePatterns: [
      /import\s+Vision/,
      /VNDetectFaceRectanglesRequest/,
      /VNDetectFaceLandmarksRequest/,
      /VNDetectFaceCaptureQualityRequest/,
      /VNFaceObservation/,
      /VNImageRequestHandler/,
    ],
  },

  {
    name: 'ARKit Face Tracking (TrueDepth)',
    vendor: 'Apple',
    biometricTypes: ['FACE_ID', 'LIVENESS'],
    platform: 'IOS',
    category: 'NATIVE_OS',
    pricingModel: 'FREE',
    reference: 'https://developer.apple.com/augmented-reality/arkit/',
    notes: 'ARKit con cámara TrueDepth para tracking facial 3D. Requiere iPhone X+.',
    codePatterns: [
      /ARFaceTrackingConfiguration/,
      /ARFaceAnchor/,
      /ARSCNFaceGeometry/,
      /blendShapes/,
      /isSupported.*faceTracking/,
    ],
  },

  // ══════════════════════════════════════════════════════════════════════════
  //  NATIVE OS — Android
  // ══════════════════════════════════════════════════════════════════════════

  {
    name: 'BiometricPrompt',
    vendor: 'Google / AOSP',
    biometricTypes: ['FACE_ID', 'FINGERPRINT', 'IRIS'],
    platform: 'ANDROID',
    category: 'NATIVE_OS',
    pricingModel: 'FREE',
    reference: 'https://developer.android.com/training/sign-in/biometric-auth',
    notes: 'API unificada de Android (API 28+) para toda biometría. Reemplaza FingerprintManager.',
    codePatterns: [
      /BiometricPrompt\s*\(/,
      /BiometricPrompt\.Builder/,
      /BiometricManager/,
      /BiometricPrompt\.AuthenticationCallback/,
      /BiometricPrompt\.CryptoObject/,
      /androidx\.biometric/,
      /BIOMETRIC_STRONG/,
      /BIOMETRIC_WEAK/,
      /setAllowedAuthenticators\s*\(/,
      /canAuthenticate\s*\(/,
    ],
  },

  {
    name: 'FingerprintManager (deprecated)',
    vendor: 'Google / AOSP',
    biometricTypes: ['FINGERPRINT'],
    platform: 'ANDROID',
    category: 'NATIVE_OS',
    pricingModel: 'FREE',
    reference: 'https://developer.android.com/reference/android/hardware/fingerprint/FingerprintManager',
    notes: 'Deprecated desde Android 9 (API 28). Solo huella dactilar. Migrar a BiometricPrompt.',
    codePatterns: [
      /FingerprintManager[^C]/,
      /fingerprintManager\.authenticate/,
      /FingerprintManager\.AuthenticationCallback/,
      /android\.hardware\.fingerprint/,
      /USE_FINGERPRINT/,
      /getSystemService.*FINGERPRINT_SERVICE/,
    ],
  },

  {
    name: 'FingerprintManagerCompat (deprecated)',
    vendor: 'Google / AOSP',
    biometricTypes: ['FINGERPRINT'],
    platform: 'ANDROID',
    category: 'NATIVE_OS',
    pricingModel: 'FREE',
    reference: 'https://developer.android.com/reference/androidx/core/hardware/fingerprint/FingerprintManagerCompat',
    notes: 'Wrapper de compatibilidad de AndroidX, también deprecated. Migrar a BiometricPrompt.',
    minSignals: 1,
    codePatterns: [
      /FingerprintManagerCompat/,
      /FingerprintManagerCompat\.from/,
      /FingerprintManagerCompat\.AuthenticationCallback/,
    ],
  },

  {
    name: 'Android Keystore (Biometric-bound)',
    vendor: 'Google / AOSP',
    biometricTypes: ['FACE_ID', 'FINGERPRINT'],
    platform: 'ANDROID',
    category: 'HARDWARE',
    pricingModel: 'FREE',
    reference: 'https://developer.android.com/training/articles/keystore',
    notes: 'Keystore con claves ligadas a biometría. Soporta StrongBox en dispositivos compatibles.',
    codePatterns: [
      /KeyGenParameterSpec\.Builder/,
      /setUserAuthenticationRequired\s*\(\s*true/,
      /setInvalidatedByBiometricEnrollment/,
      /setIsStrongBoxBacked/,
      /AndroidKeyStore/,
      /KeyProperties\.PURPOSE_ENCRYPT/,
      /KeyInfo\.isInsideSecureHardware/,
    ],
  },

  {
    name: 'ML Kit Face Detection',
    vendor: 'Google',
    biometricTypes: ['FACE_ID', 'LIVENESS'],
    platform: 'ANDROID',
    category: 'NATIVE_OS',
    pricingModel: 'FREE',
    reference: 'https://developers.google.com/ml-kit/vision/face-detection',
    notes: 'SDK on-device de Google para detección de rostros. Visión por computadora, no autenticación directa.',
    codePatterns: [
      /com\.google\.mlkit:face-detection/,
      /FaceDetection\.getClient/,
      /FaceDetectorOptions/,
      /ml\.vision\.face/,
      /com\.google\.android\.gms\.vision\.face/,
      /FaceDetector\.Builder/,
      /detectInImage\s*\(/,
    ],
    depPatterns: [/mlkit.*face|face.*mlkit/i],
  },

  // ══════════════════════════════════════════════════════════════════════════
  //  THIRD PARTY — React Native
  // ══════════════════════════════════════════════════════════════════════════

  {
    name: 'react-native-biometrics',
    vendor: 'Community OSS',
    biometricTypes: ['FACE_ID', 'FINGERPRINT'],
    platform: 'CROSS_PLATFORM',
    category: 'THIRD_PARTY',
    pricingModel: 'OPEN_SOURCE',
    reference: 'https://github.com/SelfLender/react-native-biometrics',
    notes: 'Librería OSS más popular de RN. Soporta firma de payload con clave privada en Keystore/Keychain.',
    codePatterns: [
      /react-native-biometrics/,
      /ReactNativeBiometrics/,
      /isSensorAvailable\s*\(/,
      /createKeys\s*\(/,
      /createSignature\s*\(/,
      /BiometryType\.FaceID/,
      /BiometryType\.TouchID/,
      /BiometryType\.Biometrics/,
      /deleteKeys\s*\(/,
    ],
    depPatterns: [/react-native-biometrics/],
  },

  {
    name: 'react-native-touch-id',
    vendor: 'Naoufal Kadhom',
    biometricTypes: ['FACE_ID', 'FINGERPRINT'],
    platform: 'CROSS_PLATFORM',
    category: 'THIRD_PARTY',
    pricingModel: 'OPEN_SOURCE',
    reference: 'https://github.com/naoufal/react-native-touch-id',
    notes: 'Librería original de Touch ID/Face ID para RN. Sin mantenimiento activo desde 2019.',
    codePatterns: [
      /react-native-touch-id/,
      /TouchID\.authenticate/,
      /TouchID\.isSupported/,
      /LAErrorUserCancel/,
      /LAErrorSystemCancel/,
    ],
    depPatterns: [/react-native-touch-id/],
  },

  {
    name: 'react-native-fingerprint-scanner',
    vendor: 'Hieu Nguyen',
    biometricTypes: ['FINGERPRINT', 'FACE_ID'],
    platform: 'CROSS_PLATFORM',
    category: 'THIRD_PARTY',
    pricingModel: 'OPEN_SOURCE',
    reference: 'https://github.com/hieuvp/react-native-fingerprint-scanner',
    notes: 'Wrapper OSS para biometría en RN. Sin mantenimiento activo.',
    codePatterns: [
      /react-native-fingerprint-scanner/,
      /FingerprintScanner/,
      /FingerprintScanner\.authenticate/,
      /FingerprintScanner\.isSensorAvailable/,
      /FingerprintScanner\.release/,
    ],
    depPatterns: [/react-native-fingerprint-scanner/],
  },

  {
    name: 'expo-local-authentication',
    vendor: 'Expo / Meta',
    biometricTypes: ['FACE_ID', 'FINGERPRINT', 'IRIS'],
    platform: 'CROSS_PLATFORM',
    category: 'THIRD_PARTY',
    pricingModel: 'OPEN_SOURCE',
    reference: 'https://docs.expo.dev/versions/latest/sdk/local-authentication/',
    notes: 'Módulo oficial del ecosistema Expo. Usa LocalAuthentication en iOS y BiometricPrompt en Android.',
    codePatterns: [
      /expo-local-authentication/,
      /LocalAuthentication\.authenticateAsync/,
      /LocalAuthentication\.hasHardwareAsync/,
      /LocalAuthentication\.isEnrolledAsync/,
      /LocalAuthentication\.supportedAuthenticationTypesAsync/,
      /AuthenticationType\.FINGERPRINT/,
      /AuthenticationType\.FACIAL_RECOGNITION/,
      /AuthenticationType\.IRIS/,
    ],
    depPatterns: [/expo-local-authentication/],
  },

  // ══════════════════════════════════════════════════════════════════════════
  //  THIRD PARTY — Flutter
  // ══════════════════════════════════════════════════════════════════════════

  {
    name: 'local_auth (Flutter)',
    vendor: 'Flutter Team / Google',
    biometricTypes: ['FACE_ID', 'FINGERPRINT', 'IRIS'],
    platform: 'CROSS_PLATFORM',
    category: 'THIRD_PARTY',
    pricingModel: 'OPEN_SOURCE',
    reference: 'https://pub.dev/packages/local_auth',
    notes: 'Plugin oficial de Flutter. Usa LocalAuthentication en iOS y BiometricPrompt en Android.',
    codePatterns: [
      /local_auth:/,
      /LocalAuthentication\s*\(\)/,
      /getAvailableBiometrics\s*\(/,
      /BiometricType\.face/,
      /BiometricType\.fingerprint/,
      /BiometricType\.iris/,
      /BiometricType\.strong/,
      /canCheckBiometrics/,
      /isDeviceSupported/,
    ],
    depPatterns: [/local_auth/],
  },

  {
    name: 'flutter_secure_storage',
    vendor: 'German Saprykin',
    biometricTypes: ['FACE_ID', 'FINGERPRINT'],
    platform: 'CROSS_PLATFORM',
    category: 'THIRD_PARTY',
    pricingModel: 'OPEN_SOURCE',
    reference: 'https://pub.dev/packages/flutter_secure_storage',
    notes: 'Almacenamiento seguro en Flutter con autenticación biométrica opcional para desbloquear secretos.',
    codePatterns: [
      /flutter_secure_storage/,
      /FlutterSecureStorage/,
      /IOSOptions.*biometricAccess/,
      /AndroidOptions.*encryptedSharedPreferences/,
      /secureStorage\.read/,
      /secureStorage\.write/,
    ],
    depPatterns: [/flutter_secure_storage/],
  },

  // ══════════════════════════════════════════════════════════════════════════
  //  THIRD PARTY — Capacitor / Ionic
  // ══════════════════════════════════════════════════════════════════════════

  {
    name: '@capacitor-community/fingerprint-auth',
    vendor: 'Capacitor Community',
    biometricTypes: ['FINGERPRINT', 'FACE_ID'],
    platform: 'CROSS_PLATFORM',
    category: 'THIRD_PARTY',
    pricingModel: 'OPEN_SOURCE',
    reference: 'https://github.com/capacitor-community/fingerprint-auth',
    notes: 'Plugin de la comunidad Capacitor para biometría en apps Ionic.',
    codePatterns: [
      /@capacitor-community\/fingerprint-auth/,
      /FingerprintAIO/,
      /FingerprintAIO\.isAvailable/,
      /FingerprintAIO\.show/,
      /FingerprintAIO\.registerBiometricSecret/,
    ],
    depPatterns: [/capacitor-community.*fingerprint|fingerprint-auth/i],
  },

  {
    name: '@aparajita/capacitor-biometric-auth',
    vendor: 'Aparajita Fishman',
    biometricTypes: ['FACE_ID', 'FINGERPRINT'],
    platform: 'CROSS_PLATFORM',
    category: 'THIRD_PARTY',
    pricingModel: 'OPEN_SOURCE',
    reference: 'https://github.com/aparajita/capacitor-biometric-auth',
    notes: 'Plugin moderno de Capacitor con soporte para biometría fuerte y débil.',
    codePatterns: [
      /@aparajita\/capacitor-biometric-auth/,
      /BiometricAuth\.authenticate/,
      /BiometricAuth\.checkBiometry/,
      /BiometricAuth\.setBiometryType/,
    ],
    depPatterns: [/aparajita.*biometric|capacitor-biometric-auth/i],
  },

  // ══════════════════════════════════════════════════════════════════════════
  //  THIRD PARTY — Cordova
  // ══════════════════════════════════════════════════════════════════════════

  {
    name: 'cordova-plugin-fingerprint-aio',
    vendor: 'Niklas Merz',
    biometricTypes: ['FINGERPRINT', 'FACE_ID'],
    platform: 'CROSS_PLATFORM',
    category: 'THIRD_PARTY',
    pricingModel: 'OPEN_SOURCE',
    reference: 'https://github.com/NiklasMerz/cordova-plugin-fingerprint-aio',
    notes: 'Plugin todo-en-uno de Cordova. Soporta Face ID en iOS y BiometricPrompt en Android.',
    codePatterns: [
      /cordova-plugin-fingerprint-aio/,
      /Fingerprint\.isAvailable/,
      /Fingerprint\.show/,
      /Fingerprint\.registerBiometricSecret/,
      /Fingerprint\.loadBiometricSecret/,
    ],
    depPatterns: [/fingerprint-aio/],
  },

  // ══════════════════════════════════════════════════════════════════════════
  //  STANDARD — FIDO2 / WebAuthn / Passkeys
  // ══════════════════════════════════════════════════════════════════════════

  {
    name: 'FIDO2 / WebAuthn / Passkeys',
    vendor: 'FIDO Alliance / W3C',
    biometricTypes: ['FACE_ID', 'FINGERPRINT', 'MULTI_MODAL'],
    platform: 'CROSS_PLATFORM',
    category: 'STANDARD',
    pricingModel: 'FREE',
    reference: 'https://fidoalliance.org/fido2/',
    notes: 'Estándar abierto de autenticación sin contraseña. Passkeys es la implementación moderna.',
    codePatterns: [
      /PublicKeyCredential/,
      /navigator\.credentials\.create/,
      /navigator\.credentials\.get/,
      /AuthenticatorAttestationResponse/,
      /AuthenticatorAssertionResponse/,
      /fido2ApiClient/,
      /Fido2ApiClient/,
      /com\.google\.android\.gms\.fido/,
      /BeginSignInRequest/,
      /CredentialManager/,
      /GetPublicKeyCredentialOption/,
      /CreatePublicKeyCredentialRequest/,
    ],
  },

  // ══════════════════════════════════════════════════════════════════════════
  //  KYC — Know Your Customer
  // ══════════════════════════════════════════════════════════════════════════

  {
    name: 'Jumio Netverify / KYX',
    vendor: 'Jumio Corporation',
    biometricTypes: ['FACE_ID', 'LIVENESS', 'DOCUMENT_SCAN'],
    platform: 'CROSS_PLATFORM',
    category: 'KYC',
    pricingModel: 'COMMERCIAL',
    reference: 'https://developers.jumio.com/',
    notes: 'SDK líder de KYC con verificación de documentos, face match y liveness. Ampliamente usado en fintech y banca.',
    codePatterns: [
      /jumio/i,
      /JumioMobileSDK/,
      /NetverifyMobileSDK/,
      /JumioDocumentVerification/,
      /JumioNetverify/,
      /api\.jumio\.com/,
      /JumioController/,
      /JumioDataCenter/,
      /JumioTheme/,
      /Jumio\.start/,
    ],
    depPatterns: [/jumio/i],
  },

  {
    name: 'Onfido',
    vendor: 'Onfido Ltd',
    biometricTypes: ['FACE_ID', 'LIVENESS', 'DOCUMENT_SCAN'],
    platform: 'CROSS_PLATFORM',
    category: 'KYC',
    pricingModel: 'COMMERCIAL',
    reference: 'https://documentation.onfido.com/',
    notes: 'SDK de KYC con verificación de documentos, face match y liveness. Muy usado en banca digital y seguros.',
    codePatterns: [
      /onfido/i,
      /OnfidoConfig/,
      /OnfidoFlow/,
      /Onfido\.init/,
      /api\.onfido\.com/,
      /OnfidoStudio/,
      /OnfidoTheme/,
      /WorkflowConfig/,
      /onfido-sdk-ui/,
      /OnfidoResult/,
    ],
    depPatterns: [/onfido/i],
  },

  {
    name: 'Mitek Systems (MiSnap)',
    vendor: 'Mitek Systems Inc.',
    biometricTypes: ['FACE_ID', 'LIVENESS', 'DOCUMENT_SCAN'],
    platform: 'CROSS_PLATFORM',
    category: 'KYC',
    pricingModel: 'COMMERCIAL',
    reference: 'https://www.miteksystems.com/developers',
    notes: 'Plataforma líder de KYC con MiSnap SDK para captura de documentos y selfie biométrico. Usado en banca y gobierno de USA.',
    codePatterns: [
      /mitek/i,
      /MiSnap/,
      /MiSnapFacialCapture/,
      /MiSnapDocument/,
      /MiSnapScience/,
      /miteksystems\.com/,
      /MiSnapWorkflow/,
      /MiSnapSettings/,
      /MiSnapResult/,
      /MiSnapAnalysis/,
      /MitekPlatform/,
      /MiSnapUxParameters/,
    ],
    depPatterns: [/mitek|misnap/i],
  },

  {
    name: 'LexisNexis Risk Solutions (ThreatMetrix)',
    vendor: 'LexisNexis Risk Solutions',
    biometricTypes: ['BEHAVIOR', 'FACE_ID', 'MULTI_MODAL'],
    platform: 'CROSS_PLATFORM',
    category: 'KYC',
    pricingModel: 'ENTERPRISE',
    reference: 'https://risk.lexisnexis.com/products/threatmetrix',
    notes: 'Suite de identidad digital y biometría conductual. ThreatMetrix analiza dispositivo y comportamiento para KYC y detección de fraude.',
    codePatterns: [
      /lexisnexis/i,
      /threatmetrix/i,
      /ThreatMetrix/,
      /TMXProfiling/,
      /TMXConfig/,
      /tmxsession/i,
      /LexisNexisRisk/,
      /nexisnexis\.com/,
      /threatmetrix\.com/,
      /TMXStatus/,
      /TMXProfiling\.sharedInstance/,
      /TMXEndNotifyBlock/,
    ],
    depPatterns: [/threatmetrix|lexisnexis/i],
  },

  {
    name: 'BioID',
    vendor: 'BioID GmbH',
    biometricTypes: ['FACE_ID', 'LIVENESS', 'MULTI_MODAL'],
    platform: 'CROSS_PLATFORM',
    category: 'KYC',
    pricingModel: 'COMMERCIAL',
    reference: 'https://www.bioid.com/developers/',
    notes: 'SDK alemán de verificación biométrica facial con liveness detection pasiva. Cumple eIDAS. Usado en banca y gobierno europeo.',
    codePatterns: [
      /bioid/i,
      /BioID/,
      /BioIDWebService/,
      /bioid\.com/,
      /BWS/,
      /BioIDCapture/,
      /BioIDClient/,
      /LiveDetection/,
      /bws\.bioid\.com/,
      /BioIDRestService/,
      /PhotoVerify/,
    ],
    depPatterns: [/bioid/i],
  },

  {
    name: 'FacePhi (Selphi / SelphID)',
    vendor: 'FacePhi Biometría S.A.',
    biometricTypes: ['FACE_ID', 'LIVENESS', 'DOCUMENT_SCAN'],
    platform: 'CROSS_PLATFORM',
    category: 'KYC',
    pricingModel: 'COMMERCIAL',
    reference: 'https://developers.facephi.com/',
    notes: 'SDK español de biometría facial y verificación de identidad. Líder en banca latinoamericana y europea.',
    codePatterns: [
      /facephi/i,
      /FacePhi/,
      /Selphi/,
      /SelphID/,
      /SdkSelphiActivity/,
      /SdkSelphIDActivity/,
      /FPhiSdkCore/,
      /FPhiWidget/,
      /facephi\.com/,
      /FPhiBehavioral/,
      /FPhiSelphiWidget/,
      /FPhiDocument/,
      /WidgetLoginType/,
      /FPhiSdkData/,
    ],
    depPatterns: [/facephi|selphi/i],
  },

  {
    name: 'Veriff',
    vendor: 'Veriff OÜ',
    biometricTypes: ['FACE_ID', 'LIVENESS', 'DOCUMENT_SCAN'],
    platform: 'CROSS_PLATFORM',
    category: 'KYC',
    pricingModel: 'COMMERCIAL',
    reference: 'https://developers.veriff.com/',
    notes: 'SDK de KYC con selfie biométrico y análisis de documentos de identidad. Popular en fintechs europeas.',
    codePatterns: [
      /veriff/i,
      /VeriffSdk/,
      /VeriffConfig/,
      /stationsdk\.veriff\.com/,
      /Veriff\.createVeriffSession/,
      /VeriffResult/,
      /VeriffListener/,
    ],
    depPatterns: [/veriff/i],
  },

  {
    name: 'Acuant / HyperVerge',
    vendor: 'Acuant / HyperVerge Inc.',
    biometricTypes: ['FACE_ID', 'LIVENESS', 'DOCUMENT_SCAN'],
    platform: 'CROSS_PLATFORM',
    category: 'KYC',
    pricingModel: 'COMMERCIAL',
    reference: 'https://docs.acuant.com/',
    notes: 'SDK de KYC con captura de documentos y face match. HyperVerge tiene fuerte presencia en Asia y LATAM.',
    codePatterns: [
      /acuant/i,
      /AcuantCamera/,
      /AcuantFaceCapture/,
      /AcuantDocumentProcessing/,
      /hyperverge/i,
      /HVFaceConfig/,
      /HVNetworkHelper/,
      /HVDocsConfig/,
      /AcuantPassiveLiveness/,
    ],
    depPatterns: [/acuant|hyperverge/i],
  },

  {
    name: 'Persona (withpersona)',
    vendor: 'Persona Identities Inc.',
    biometricTypes: ['FACE_ID', 'LIVENESS', 'DOCUMENT_SCAN'],
    platform: 'CROSS_PLATFORM',
    category: 'KYC',
    pricingModel: 'COMMERCIAL',
    reference: 'https://docs.withpersona.com/',
    notes: 'Plataforma de KYC/identity verification. Popular en fintechs y marketplaces de USA.',
    codePatterns: [
      /withpersona/i,
      /PersonaSDK/,
      /Persona\.createInquiry/,
      /InquiryBuilder/,
      /withpersona\.com/,
      /PersonaInquiry/,
      /InquiryDelegate/,
    ],
    depPatterns: [/persona.*kyc|withpersona/i],
  },

  {
    name: 'Stripe Identity',
    vendor: 'Stripe Inc.',
    biometricTypes: ['FACE_ID', 'LIVENESS', 'DOCUMENT_SCAN'],
    platform: 'CROSS_PLATFORM',
    category: 'KYC',
    pricingModel: 'COMMERCIAL',
    reference: 'https://stripe.com/docs/identity',
    notes: 'SDK de verificación de identidad de Stripe con selfie biométrico y documentos. Integrado en el ecosistema de pagos Stripe.',
    codePatterns: [
      /StripeIdentity/,
      /stripe.*identity/i,
      /IdentityVerificationSheet/,
      /IdentityVerificationSheet\.create/,
      /stripe\.com\/v1\/identity/,
      /verificationSession/,
    ],
    depPatterns: [/stripe.*identity|stripeidentity/i],
  },

  {
    name: 'Socure',
    vendor: 'Socure Inc.',
    biometricTypes: ['FACE_ID', 'LIVENESS', 'DOCUMENT_SCAN'],
    platform: 'CROSS_PLATFORM',
    category: 'KYC',
    pricingModel: 'COMMERCIAL',
    reference: 'https://developer.socure.com/',
    notes: 'Plataforma de KYC/identity verification con ML para detección de fraude. Muy usado en banca y seguros de USA.',
    codePatterns: [
      /socure/i,
      /SocureSDK/,
      /DocVSDK/,
      /socure\.com/,
      /SocureConfig/,
      /SocureResult/,
      /Predictive.*DocV/,
    ],
    depPatterns: [/socure/i],
  },

  {
    name: 'Au10tix',
    vendor: 'Au10tix Ltd.',
    biometricTypes: ['FACE_ID', 'LIVENESS', 'DOCUMENT_SCAN'],
    platform: 'CROSS_PLATFORM',
    category: 'KYC',
    pricingModel: 'COMMERCIAL',
    reference: 'https://developers.au10tix.com/',
    notes: 'Verificación de identidad con selfie biométrico y análisis de documentos. Fuerte en transporte y finanzas.',
    codePatterns: [
      /au10tix/i,
      /Au10tix/,
      /au10tixsdk/i,
      /au10tix\.com/,
      /ATXSession/,
      /Au10tixResult/,
    ],
    depPatterns: [/au10tix/i],
  },

  {
    name: 'Shufti Pro',
    vendor: 'Shufti Pro Ltd.',
    biometricTypes: ['FACE_ID', 'LIVENESS', 'DOCUMENT_SCAN'],
    platform: 'CROSS_PLATFORM',
    category: 'KYC',
    pricingModel: 'COMMERCIAL',
    reference: 'https://developers.shuftipro.com/',
    notes: 'Servicio de KYC/AML con verificación facial y documentos. Popular en cripto, fintech y gaming.',
    codePatterns: [
      /shuftipro/i,
      /ShuftiPro/,
      /shuftipro\.com/,
      /ShuftiSDK/,
      /ShuftiVerification/,
    ],
    depPatterns: [/shuftipro/i],
  },

  {
    name: 'iDenfy',
    vendor: 'UAB iDenfy',
    biometricTypes: ['FACE_ID', 'LIVENESS', 'DOCUMENT_SCAN'],
    platform: 'CROSS_PLATFORM',
    category: 'KYC',
    pricingModel: 'COMMERCIAL',
    reference: 'https://documentation.idenfy.com/',
    notes: 'Plataforma de KYC con selfie y liveness detection. Empresa lituana con foco en mercado europeo.',
    codePatterns: [
      /idenfy/i,
      /IdenfySDK/,
      /idenfy\.com/,
      /IdenfyController/,
      /IdenfyResult/,
      /IdenfyUISettings/,
    ],
    depPatterns: [/idenfy/i],
  },

  {
    name: 'ComplyCube',
    vendor: 'ComplyCube Ltd.',
    biometricTypes: ['FACE_ID', 'LIVENESS', 'DOCUMENT_SCAN'],
    platform: 'CROSS_PLATFORM',
    category: 'KYC',
    pricingModel: 'COMMERCIAL',
    reference: 'https://docs.complycube.com/',
    notes: 'Plataforma de KYC/AML con verificación biométrica, documentos y comprobaciones de antecedentes.',
    codePatterns: [
      /complycube/i,
      /ComplyCube/,
      /complycube\.com/,
      /ComplyCubeSDK/,
      /ComplyCubeResult/,
    ],
    depPatterns: [/complycube/i],
  },

  {
    name: 'Sumsub',
    vendor: 'Sum and Substance Ltd.',
    biometricTypes: ['FACE_ID', 'LIVENESS', 'DOCUMENT_SCAN'],
    platform: 'CROSS_PLATFORM',
    category: 'KYC',
    pricingModel: 'COMMERCIAL',
    reference: 'https://developers.sumsub.com/',
    notes: 'Plataforma de KYC/AML con verificación de identidad y liveness. Muy usado en cripto y fintech europeo.',
    codePatterns: [
      /sumsub/i,
      /Sumsub/,
      /sumsub\.com/,
      /SNSMobileSDK/,
      /SumsubSDK/,
      /SNSFlowConfig/,
      /sumsubToken/i,
    ],
    depPatterns: [/sumsub/i],
  },

  {
    name: 'Trulioo',
    vendor: 'Trulioo Information Services Inc.',
    biometricTypes: ['FACE_ID', 'LIVENESS', 'DOCUMENT_SCAN'],
    platform: 'CROSS_PLATFORM',
    category: 'KYC',
    pricingModel: 'COMMERCIAL',
    reference: 'https://developer.trulioo.com/',
    notes: 'Plataforma global de KYC con verificación de identidad en más de 195 países.',
    codePatterns: [
      /trulioo/i,
      /Trulioo/,
      /trulioo\.com/,
      /TruliooSDK/,
      /GlobalGateway/,
      /truliooResult/i,
    ],
    depPatterns: [/trulioo/i],
  },

  {
    name: 'IDnow',
    vendor: 'IDnow GmbH',
    biometricTypes: ['FACE_ID', 'LIVENESS', 'DOCUMENT_SCAN'],
    platform: 'CROSS_PLATFORM',
    category: 'KYC',
    pricingModel: 'COMMERCIAL',
    reference: 'https://www.idnow.io/developers/',
    notes: 'Plataforma alemana de eKYC con identificación por video, AutoIdent y QES. Cumple normativas AML5 y eIDAS.',
    codePatterns: [
      /idnow/i,
      /IDnow/,
      /idnow\.io/,
      /IDnowSDK/,
      /AutoIdent/,
      /VideoIdent/,
      /IDnowResult/,
    ],
    depPatterns: [/idnow/i],
  },

  {
    name: 'Nethone',
    vendor: 'Nethone (Mangopay)',
    biometricTypes: ['BEHAVIOR'],
    platform: 'CROSS_PLATFORM',
    category: 'KYC',
    pricingModel: 'COMMERCIAL',
    reference: 'https://www.nethone.com/',
    notes: 'Plataforma de inteligencia de fraude con biometría conductual y device fingerprinting. Adquirida por Mangopay.',
    codePatterns: [
      /nethone/i,
      /Nethone/,
      /nethone\.com/,
      /NethoneSDK/,
      /NethoneAttempt/,
    ],
    depPatterns: [/nethone/i],
  },

  // ══════════════════════════════════════════════════════════════════════════
  //  COMMERCIAL — Biometría sin KYC completo
  // ══════════════════════════════════════════════════════════════════════════

  {
    name: 'iProov',
    vendor: 'iProov Ltd',
    biometricTypes: ['FACE_ID', 'LIVENESS'],
    platform: 'CROSS_PLATFORM',
    category: 'COMMERCIAL',
    pricingModel: 'COMMERCIAL',
    reference: 'https://docs.iproov.com/',
    notes: 'Liveness detection con tecnología GPA (Genuine Presence Assurance). Usado en banca, gobierno y salud. Integrable dentro de flujos KYC.',
    codePatterns: [
      /iproov/i,
      /IProov/,
      /iProovSDK/,
      /api\.iproov\.com/,
      /IProovConfig/,
      /IProovSessionError/,
      /GenuinePresenceResult/,
      /IProovUi/,
    ],
    depPatterns: [/iproov/i],
  },

  {
    name: 'BioCatch',
    vendor: 'BioCatch Ltd',
    biometricTypes: ['BEHAVIOR'],
    platform: 'CROSS_PLATFORM',
    category: 'COMMERCIAL',
    pricingModel: 'COMMERCIAL',
    reference: 'https://www.biocatch.com/',
    notes: 'Biometría conductual: patrones de tipeo, gestos y movimiento para autenticación continua y detección de fraude bancario.',
    codePatterns: [
      /biocatch/i,
      /BioCatch/,
      /BCClient/,
      /startSession.*biocatch/i,
      /biocatch\.com/,
      /BCConfiguration/,
    ],
    depPatterns: [/biocatch/i],
  },

  {
    name: 'TypingDNA',
    vendor: 'TypingDNA',
    biometricTypes: ['BEHAVIOR'],
    platform: 'CROSS_PLATFORM',
    category: 'COMMERCIAL',
    pricingModel: 'FREEMIUM',
    reference: 'https://www.typingdna.com/docs',
    notes: 'Biometría conductual basada en patrones de tipeo. Usable como segundo factor de autenticación.',
    codePatterns: [
      /typingdna/i,
      /TypingDNA/,
      /typingdna\.com/,
      /tdna/i,
      /TypingDNARecorder/,
      /getTypingPattern/,
    ],
    depPatterns: [/typingdna/i],
  },

  {
    name: 'Sensory TrulySecure',
    vendor: 'Sensory Inc.',
    biometricTypes: ['FACE_ID', 'VOICE'],
    platform: 'CROSS_PLATFORM',
    category: 'COMMERCIAL',
    pricingModel: 'COMMERCIAL',
    reference: 'https://www.sensory.com/trulysecure/',
    notes: 'SDK de autenticación biométrica multimodal (voz + rostro). Funciona on-device o en cloud.',
    codePatterns: [
      /sensory/i,
      /TrulySecure/,
      /sensory\.com/,
      /SensorySDK/,
      /TrulySecureActivity/,
      /SensoryVerification/,
    ],
    depPatterns: [/sensory.*truly|trulysecure/i],
  },

  // ══════════════════════════════════════════════════════════════════════════
  //  CLOUD API
  // ══════════════════════════════════════════════════════════════════════════

  {
    name: 'AWS Rekognition',
    vendor: 'Amazon Web Services',
    biometricTypes: ['FACE_ID', 'LIVENESS'],
    platform: 'CROSS_PLATFORM',
    category: 'CLOUD_API',
    pricingModel: 'FREEMIUM',
    reference: 'https://docs.aws.amazon.com/rekognition/',
    notes: 'API cloud de análisis facial de Amazon. Incluye FaceLiveness para detección de presencia real.',
    codePatterns: [
      /RekognitionClient/,
      /rekognition\.detectFaces/,
      /rekognition\.compareFaces/,
      /rekognition\.searchFacesByImage/,
      /rekognition\.createCollection/,
      /rekognition\.indexFaces/,
      /amazonaws\.com\/rekognition/,
      /CreateFaceLivenessSession/,
      /GetFaceLivenessSessionResults/,
      /aws-amplify.*predictions/,
      /Predictions\.identify.*faces/,
    ],
    depPatterns: [/rekognition|aws.*face/i],
  },

  {
    name: 'Azure Face API',
    vendor: 'Microsoft',
    biometricTypes: ['FACE_ID', 'LIVENESS'],
    platform: 'CROSS_PLATFORM',
    category: 'CLOUD_API',
    pricingModel: 'FREEMIUM',
    reference: 'https://learn.microsoft.com/en-us/azure/ai-services/computer-vision/overview-identity',
    notes: 'API de reconocimiento facial de Microsoft Azure. Incluye Face Liveness Detection.',
    codePatterns: [
      /FaceClient/,
      /face\.detect/,
      /face\.verify/,
      /face\.identify/,
      /azure\.com.*face/,
      /cognitiveservices\.azure\.com/,
      /CognitiveServicesCredentials/,
      /PersonGroup/,
      /FaceList/,
    ],
    depPatterns: [/azure.*face|microsoft.*face/i],
  },

  {
    name: 'Google Cloud Vision (Face)',
    vendor: 'Google Cloud',
    biometricTypes: ['FACE_ID'],
    platform: 'CROSS_PLATFORM',
    category: 'CLOUD_API',
    pricingModel: 'FREEMIUM',
    reference: 'https://cloud.google.com/vision/docs/detecting-faces',
    notes: 'API cloud de Google para detección de rostros mediante análisis de imágenes.',
    codePatterns: [
      /vision\.googleapis\.com/,
      /ImageAnnotatorClient/,
      /FACE_DETECTION/,
      /FaceAnnotation/,
      /faceDetection\s*\(/,
      /batchAnnotateImages/,
      /@google-cloud\/vision/,
    ],
    depPatterns: [/@google-cloud\/vision/],
  },

  {
    name: 'FaceIO',
    vendor: 'FaceIO (pixlab.io)',
    biometricTypes: ['FACE_ID', 'LIVENESS'],
    platform: 'CROSS_PLATFORM',
    category: 'CLOUD_API',
    pricingModel: 'FREEMIUM',
    reference: 'https://faceio.net/getting-started',
    notes: 'Plataforma SaaS de autenticación facial vía webcam/cámara. Modelo freemium.',
    codePatterns: [
      /faceio/i,
      /fio\.init/,
      /faceIO\.enroll/,
      /faceIO\.authenticate/,
      /cdn\.faceio\.net/,
      /api\.faceio\.net/,
      /FACEIO_APP_PUBLIC_ID/,
    ],
    depPatterns: [/faceio/i],
  },

  {
    name: 'Face++ (Megvii)',
    vendor: 'Megvii Technology',
    biometricTypes: ['FACE_ID', 'LIVENESS'],
    platform: 'CROSS_PLATFORM',
    category: 'CLOUD_API',
    pricingModel: 'FREEMIUM',
    reference: 'https://www.faceplusplus.com/face-recognition/',
    notes: 'API de reconocimiento facial de Megvii. Popular en apps de Asia-Pacífico.',
    codePatterns: [
      /faceplusplus/i,
      /face\+\+/i,
      /FacePP/,
      /api\.faceplusplus\.com/,
      /MegviiFaceSDK/,
      /FaceSet/,
    ],
    depPatterns: [/faceplusplus|facePP/i],
  },

  {
    name: 'Kairos',
    vendor: 'Kairos AR Inc.',
    biometricTypes: ['FACE_ID'],
    platform: 'CROSS_PLATFORM',
    category: 'CLOUD_API',
    pricingModel: 'COMMERCIAL',
    reference: 'https://www.kairos.com/docs',
    notes: 'API cloud de reconocimiento facial enfocada en privacidad y sesgo mínimo.',
    codePatterns: [
      /kairos/i,
      /api\.kairos\.com/,
      /KairosClient/,
      /kairos\.enroll/,
      /kairos\.recognize/,
    ],
    depPatterns: [/kairos/i],
  },

  {
    name: 'DeepFace (Clarifai)',
    vendor: 'Clarifai Inc.',
    biometricTypes: ['FACE_ID'],
    platform: 'CROSS_PLATFORM',
    category: 'CLOUD_API',
    pricingModel: 'FREEMIUM',
    reference: 'https://docs.clarifai.com/api-guide/predict/visual-detection/',
    notes: 'API cloud de reconocimiento facial de Clarifai con modelos de detección y reconocimiento.',
    codePatterns: [
      /clarifai/i,
      /ClarifaiStub/,
      /clarifai\.com/,
      /ClarifaiApp/,
      /face.*clarifai/i,
      /models\.predict/,
    ],
    depPatterns: [/clarifai/i],
  },

  // ══════════════════════════════════════════════════════════════════════════
  //  ENTERPRISE
  // ══════════════════════════════════════════════════════════════════════════

  {
    name: 'IDEMIA (MorphoKit)',
    vendor: 'IDEMIA',
    biometricTypes: ['FACE_ID', 'FINGERPRINT', 'IRIS'],
    platform: 'CROSS_PLATFORM',
    category: 'ENTERPRISE',
    pricingModel: 'ENTERPRISE',
    reference: 'https://developer.idemia.com/',
    notes: 'SDK enterprise de IDEMIA (ex Morpho). Gobierno, aeropuertos, banca central y fuerzas de seguridad.',
    codePatterns: [
      /idemia/i,
      /IDEMIA/,
      /MorphoKit/,
      /MorphoSmartSDK/,
      /morpho/i,
      /idemia\.io/,
      /IdemiaSDK/,
      /BioStore/,
    ],
    depPatterns: [/idemia|morpho/i],
  },

  {
    name: 'Daon IdentityX',
    vendor: 'Daon Inc.',
    biometricTypes: ['FACE_ID', 'FINGERPRINT', 'VOICE', 'IRIS'],
    platform: 'CROSS_PLATFORM',
    category: 'ENTERPRISE',
    pricingModel: 'ENTERPRISE',
    reference: 'https://developer.daon.com/',
    notes: 'Plataforma FIDO-certified de biometría multimodal. Muy usado en banca, aerolíneas y gobierno.',
    codePatterns: [
      /daon/i,
      /IdentityX/,
      /DaonAuthenticator/,
      /daon\.com/,
      /ixSDK/,
      /IXAController/,
      /DaonFace/,
      /DaonVoice/,
    ],
    depPatterns: [/daon/i],
  },

  {
    name: 'AWARE Biometrics (Knomi)',
    vendor: 'AWARE Inc.',
    biometricTypes: ['FACE_ID', 'FINGERPRINT', 'IRIS', 'VOICE'],
    platform: 'CROSS_PLATFORM',
    category: 'ENTERPRISE',
    pricingModel: 'ENTERPRISE',
    reference: 'https://www.aware.com/biometrics-software/knomi/',
    notes: 'Suite mobile de biometría enterprise con liveness detection activa y pasiva (Knomi). Banca y gobierno.',
    codePatterns: [
      /awarebio/i,
      /AwareBiometrics/,
      /knomi/i,
      /WebEnrollSDK/,
      /faceLiveness/,
      /aware\.com/,
      /KnomiConfig/,
    ],
    depPatterns: [/aware.*bio|knomi/i],
  },

  {
    name: 'NEC NeoFace',
    vendor: 'NEC Corporation',
    biometricTypes: ['FACE_ID'],
    platform: 'CROSS_PLATFORM',
    category: 'ENTERPRISE',
    pricingModel: 'ENTERPRISE',
    reference: 'https://www.nec.com/en/global/solutions/biometrics/face/',
    notes: 'Motor de reconocimiento facial de NEC. Aeropuertos, estadios y fuerzas de seguridad a nivel mundial.',
    codePatterns: [
      /NeoFace/,
      /nec.*biometric/i,
      /necam\.com/,
      /NeoFaceSDK/,
      /NFWatchPatrol/,
    ],
    depPatterns: [/neoface|nec.*face/i],
  },

  {
    name: 'Veridium',
    vendor: 'Veridium Ltd.',
    biometricTypes: ['FINGERPRINT', 'FACE_ID', 'BEHAVIOR'],
    platform: 'CROSS_PLATFORM',
    category: 'ENTERPRISE',
    pricingModel: 'ENTERPRISE',
    reference: 'https://www.veridiumid.com/developers/',
    notes: 'Plataforma enterprise FIDO-certified. Incluye 4 Fingers TouchID. Banca corporativa.',
    codePatterns: [
      /veridium/i,
      /VeridiumSDK/,
      /4FingersTouchID/,
      /veridiumid\.com/,
      /VeridiumAD/,
    ],
    depPatterns: [/veridium/i],
  },

  {
    name: 'Nuance Gatekeeper',
    vendor: 'Nuance / Microsoft',
    biometricTypes: ['VOICE', 'FACE_ID'],
    platform: 'CROSS_PLATFORM',
    category: 'ENTERPRISE',
    pricingModel: 'ENTERPRISE',
    reference: 'https://www.nuance.com/omni-channel-customer-engagement/authentication-and-fraud-prevention/biometric-authentication.html',
    notes: 'SDK de biometría de voz y face de Nuance (adquirida por Microsoft). Contact centers y banca telefónica.',
    codePatterns: [
      /nuance/i,
      /NuanceBiometric/,
      /VocalPassword/,
      /nuance\.com.*biometrics/,
      /GatekeeperSDK/,
      /NuanceVoiceAuth/,
    ],
    depPatterns: [/nuance.*bio|gatekeeper.*nuance/i],
  },

  {
    name: 'Thales (Gemalto) Biometric SDK',
    vendor: 'Thales Group',
    biometricTypes: ['FACE_ID', 'FINGERPRINT'],
    platform: 'CROSS_PLATFORM',
    category: 'ENTERPRISE',
    pricingModel: 'ENTERPRISE',
    reference: 'https://cpl.thalesgroup.com/access-management/authenticators/biometric-authentication',
    notes: 'SDK enterprise de Thales (ex Gemalto) para biometría en documentos de identidad y banca.',
    codePatterns: [
      /thales/i,
      /gemalto/i,
      /ThalesBiometric/,
      /GemaltoFace/,
      /SafeNet.*biometric/i,
      /thalesgroup\.com/,
    ],
    depPatterns: [/thales.*bio|gemalto/i],
  },

  {
    name: 'Innovatrics DOT',
    vendor: 'Innovatrics s.r.o.',
    biometricTypes: ['FACE_ID', 'FINGERPRINT', 'IRIS', 'LIVENESS'],
    platform: 'CROSS_PLATFORM',
    category: 'ENTERPRISE',
    pricingModel: 'ENTERPRISE',
    reference: 'https://developers.innovatrics.com/digital-onboarding/',
    notes: 'SDK biométrico enterprise europeo (Digital Onboarding Toolkit). Especializado en onboarding bancario.',
    codePatterns: [
      /innovatrics/i,
      /DOTFaceCore/,
      /DOTDocument/,
      /DotSdk/,
      /innovatrics\.com/,
      /DOTFaceCamera/,
      /DOTLiveness/,
    ],
    depPatterns: [/innovatrics|dot.*sdk/i],
  },

  {
    name: 'Paravision',
    vendor: 'Paravision',
    biometricTypes: ['FACE_ID', 'LIVENESS'],
    platform: 'CROSS_PLATFORM',
    category: 'ENTERPRISE',
    pricingModel: 'ENTERPRISE',
    reference: 'https://www.paravision.ai/',
    notes: 'Motor de reconocimiento facial de alta precisión para control de acceso, viajes y gobierno.',
    codePatterns: [
      /paravision/i,
      /ParavisionSDK/,
      /paravision\.ai/,
      /PVFaceSDK/,
    ],
    depPatterns: [/paravision/i],
  },

  {
    name: 'Rank One Computing (ROC)',
    vendor: 'Rank One Computing',
    biometricTypes: ['FACE_ID', 'FINGERPRINT', 'IRIS'],
    platform: 'CROSS_PLATFORM',
    category: 'ENTERPRISE',
    pricingModel: 'ENTERPRISE',
    reference: 'https://roc.ai/sdk/',
    notes: 'SDK biométrico multimodal de alta performance para aplicaciones de seguridad y control de acceso.',
    codePatterns: [
      /rankone/i,
      /roc\.ai/,
      /ROCFace/,
      /ROCSdk/,
      /RankOneSdk/,
    ],
    depPatterns: [/rankone|roc.*sdk/i],
  },
]

// ─────────────────────────────────────────────────────────────────────────────
//  Analyzer
// ─────────────────────────────────────────────────────────────────────────────

export class FaceIdAnalyzer {
  constructor(
    private readonly extractPath: string,
    private readonly platform?: 'ANDROID' | 'IOS'
  ) {}

  async analyze(): Promise<FaceIdAnalysisResult> {
    logger.info('🪪 Analyzing biometric / FaceID frameworks...')

    const { sourceFiles, depFiles } = this.collectFiles(this.extractPath)
    const scannedFiles = sourceFiles.length + depFiles.length

    if (scannedFiles === 0) {
      logger.warn('🪪 No files found for biometric analysis')
      return this.emptyResult(0)
    }

    
    const hits = new Map<number, { signals: number; evidence: FrameworkEvidence[] }>()

    
    for (const filePath of sourceFiles) {
      const content = this.safeRead(filePath)
      if (!content) continue

      const lines = content.split('\n')
      const rel = path.relative(this.extractPath, filePath)

      for (let si = 0; si < SIGNATURES.length; si++) {
        for (const pattern of SIGNATURES[si].codePatterns) {
          for (let li = 0; li < lines.length; li++) {
            if (pattern.test(lines[li])) {
              const entry = hits.get(si) ?? { signals: 0, evidence: [] }
              entry.signals++
              entry.evidence.push({
                file: rel,
                line: li + 1,
                snippet: this.sanitizeText(lines[li].trim()),
                matchedPattern: pattern.source,
              })
              hits.set(si, entry)
              break
            }
          }
        }
      }
    }

    // ── dependency / manifest files ───────────────────────────────────────────
    for (const filePath of depFiles) {
      const content = this.safeRead(filePath)
      if (!content) continue

      const lines = content.split('\n')
      const rel = path.relative(this.extractPath, filePath)

      for (let si = 0; si < SIGNATURES.length; si++) {
        const sig = SIGNATURES[si]
        if (!sig.depPatterns) continue

        for (const pattern of sig.depPatterns) {
          for (let li = 0; li < lines.length; li++) {
            if (pattern.test(lines[li])) {
              const entry = hits.get(si) ?? { signals: 0, evidence: [] }
              entry.signals += 2
              entry.evidence.push({
                file: rel,
                line: li + 1,
                snippet: this.sanitizeText(lines[li].trim()),
                matchedPattern: this.sanitizeText(`[dep] ${pattern.source}`, 200),
              })
              hits.set(si, entry)
              break
            }
          }
        }
      }
    }

    // ── build result ──────────────────────────────────────────────────────────
    const detectedFrameworks: DetectedFramework[] = []

    for (const [si, hit] of hits.entries()) {
      const sig = SIGNATURES[si]
      const required = sig.minSignals ?? MIN_SIGNALS
      if (hit.signals < required) continue

      const confidence: ConfidenceLevel =
        hit.signals >= 5 ? 'HIGH' :
        hit.signals >= 2 ? 'MEDIUM' : 'LOW'

      detectedFrameworks.push({
        name: sig.name,
        version: this.extractVersion(hit.evidence),
        vendor: sig.vendor,
        biometricTypes: sig.biometricTypes,
        platform: sig.platform,
        category: sig.category,
        pricingModel: sig.pricingModel,
        confidence,
        reference: sig.reference,
        notes: sig.notes,
        evidence: hit.evidence,
        signalCount: hit.signals,
      })
    }

    detectedFrameworks.sort((a, b) => {
      const order: Record<ConfidenceLevel, number> = { HIGH: 0, MEDIUM: 1, LOW: 2 }
      const diff = order[a.confidence] - order[b.confidence]
      return diff !== 0 ? diff : b.signalCount - a.signalCount
    })

    const biometricTypes = this.collectBiometricTypes(detectedFrameworks)
    const summary = this.buildSummary(detectedFrameworks)

    logger.info(
      `🪪 FaceID analyzed: ${detectedFrameworks.length} frameworks detected, ` +
      `types=[${biometricTypes.join(',')}], ` +
      `kyc=${summary.hasKycSdk}, commercial=${summary.hasCommercialSdk}, ` +
      `enterprise=${summary.hasEnterpriseGrade}`
    )

    return {
      hasBiometrics: detectedFrameworks.length > 0,
      detectedFrameworks,
      biometricTypes,
      scannedFiles,
      summary,
    }
  }

  // ── File collection ───────────────────────────────────────────────────────

    private sanitizeText(raw: string, maxLen = 140): string {
    return raw
      .replace(/\u0000/g, '')
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '') 
      .slice(0, maxLen)
  }

  private collectFiles(dir: string): { sourceFiles: string[]; depFiles: string[] } {
    const sourceFiles: string[] = []
    const depFiles: string[] = []

    if (!fs.existsSync(dir)) return { sourceFiles, depFiles }

    const recurse = (current: string) => {
      let entries: fs.Dirent[]
      try { entries = fs.readdirSync(current, { withFileTypes: true }) }
      catch { return }

      for (const entry of entries) {
        const full = path.join(current, entry.name)
        if (entry.isDirectory()) {
          if (!SKIP_DIRS.has(entry.name)) recurse(full)
        } else if (entry.isFile()) {
          const lower = entry.name.toLowerCase()
          if (DEP_FILENAMES.has(lower)) {
            depFiles.push(full)
          } else if (SCAN_EXTENSIONS.has(path.extname(lower))) {
            sourceFiles.push(full)
          }
        }
      }
    }

    recurse(dir)
    return { sourceFiles, depFiles }
  }

  private safeRead(filePath: string): string | null {
    try {
      const stat = fs.statSync(filePath)
      if (stat.size > MAX_FILE_BYTES) return null
 
      const raw = fs.readFileSync(filePath, 'utf-8')
 
      // Strip null bytes early — binaries (.so, .dylib) los contienen
      // eslint-disable-next-line no-control-regex
      return raw.replace(/\u0000/g, '').replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '')
    } catch {
      return null
    }
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  /** Try to extract version string from dependency snippets like "lib": "^3.0.1" */
  private extractVersion(evidence: FrameworkEvidence[]): string | undefined {
    const re = /"[\w\-@/]+":\s*"[\^~]?(\d+\.\d+[\.\d]*)"/
    for (const ev of evidence) {
      const m = ev.snippet.match(re)
      if (m) return m[1]
    }
    return undefined
  }

  private collectBiometricTypes(frameworks: DetectedFramework[]): BiometricType[] {
    const types = new Set<BiometricType>()
    for (const f of frameworks) f.biometricTypes.forEach(t => types.add(t))
    return Array.from(types)
  }

  private buildSummary(frameworks: DetectedFramework[]): AnalysisSummary {
    const byCategory: Record<FrameworkCategory, string[]> = {
      NATIVE_OS: [], THIRD_PARTY: [], KYC: [],
      COMMERCIAL: [], CLOUD_API: [], ENTERPRISE: [],
      STANDARD: [], HARDWARE: [],
    }

    for (const f of frameworks) byCategory[f.category].push(f.name)

    return {
      byCategory,
      totalFrameworks: frameworks.length,
      hasKycSdk: byCategory.KYC.length > 0,
      hasCommercialSdk: byCategory.COMMERCIAL.length > 0,
      hasCloudApi: byCategory.CLOUD_API.length > 0,
      hasEnterpriseGrade: byCategory.ENTERPRISE.length > 0,
      hasNativeOnly:
        frameworks.length > 0 &&
        byCategory.KYC.length === 0 &&
        byCategory.COMMERCIAL.length === 0 &&
        byCategory.CLOUD_API.length === 0 &&
        byCategory.ENTERPRISE.length === 0 &&
        byCategory.THIRD_PARTY.length === 0,
    }
  }

  private emptyResult(scannedFiles: number): FaceIdAnalysisResult {
    const byCategory: Record<FrameworkCategory, string[]> = {
      NATIVE_OS: [], THIRD_PARTY: [], KYC: [],
      COMMERCIAL: [], CLOUD_API: [], ENTERPRISE: [],
      STANDARD: [], HARDWARE: [],
    }
    return {
      hasBiometrics: false,
      detectedFrameworks: [],
      biometricTypes: [],
      scannedFiles,
      summary: {
        byCategory,
        totalFrameworks: 0,
        hasKycSdk: false,
        hasCommercialSdk: false,
        hasCloudApi: false,
        hasEnterpriseGrade: false,
        hasNativeOnly: false,
      },
    }
  }
}